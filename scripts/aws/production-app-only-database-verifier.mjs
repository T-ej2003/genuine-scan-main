// This function is also serialized as the fixed, protected-source task command.
// It has no CLI/SQL/command overrides and requires one explicit Prisma
// transaction, avoiding pool-dependent BEGIN/query/COMMIT on different sessions.
export async function collectAppOnlyDatabaseCatalogueRows(tx, validateIdentity = () => {}) {
    // PostgreSQL deparsers consult the effective search path. Pin it locally so
    // identical durable state hashes identically for every authorized principal.
    await tx.$executeRawUnsafe("SET LOCAL search_path = pg_catalog");
    const [identity] = await tx.$queryRawUnsafe(`SELECT current_user AS role, session_user AS session_role,
      current_database() AS database, current_setting('server_version_num')::integer AS server_version_num,
      current_setting('transaction_read_only') AS read_only,
      current_setting('default_transaction_read_only') AS default_read_only,
      r.rolsuper, r.rolinherit, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls,
      EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=r.oid) AS memberships,
      EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'
          AND (c.relowner=r.oid OR (c.relkind IN ('r','p','v','m','f') AND
          (pg_catalog.has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') OR
           pg_catalog.has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE'))))) AS write_privileges,
      EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname NOT LIKE 'pg_%'
        AND (n.nspowner=r.oid OR pg_catalog.has_schema_privilege(r.oid,n.oid,'CREATE'))) AS schema_write,
      pg_catalog.has_database_privilege(current_user,current_database(),'CREATE,TEMPORARY') AS database_write
      FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`);
    validateIdentity(identity);
    // Metadata only: never invoke application functions, including SECURITY
    // DEFINER canaries. Qualify all catalogue functions and relations.
    const [securityExtensions] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.name),'[]'::jsonb) AS rows FROM (
      SELECT e.extname AS name,e.extversion AS version,n.nspname AS schema,e.extrelocatable AS relocatable,o.rolname AS owner
      FROM pg_catalog.pg_extension e JOIN pg_catalog.pg_namespace n ON n.oid=e.extnamespace
      JOIN pg_catalog.pg_roles o ON o.oid=e.extowner
    ) x`);
    const [securityBindings] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.kind,x.name),'[]'::jsonb) AS rows FROM (
      SELECT 'publication' AS kind,p.pubname AS name,o.rolname AS owner,jsonb_build_object('all_tables',p.puballtables,'insert',p.pubinsert,
        'update',p.pubupdate,'delete',p.pubdelete,'truncate',p.pubtruncate,'via_root',p.pubviaroot,'generated_columns',p.pubgencols) AS definition
      FROM pg_catalog.pg_publication p JOIN pg_catalog.pg_roles o ON o.oid=p.pubowner
      UNION ALL
      SELECT 'subscription',s.subname,o.rolname,jsonb_build_object('enabled',s.subenabled,'binary',s.subbinary,'streaming',s.substream,
        'two_phase',s.subtwophasestate,'disable_on_error',s.subdisableonerr,'password_required',s.subpasswordrequired,'run_as_owner',s.subrunasowner,
        'failover',s.subfailover,'slot_name',s.subslotname,'synchronous_commit',s.subsynccommit,'publications',s.subpublications,'origin',s.suborigin)
      FROM pg_catalog.pg_subscription s JOIN pg_catalog.pg_roles o ON o.oid=s.subowner
      WHERE s.subdbid=(SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname=current_database())
      UNION ALL
      SELECT 'operator',pg_catalog.format('%I.%I(%s,%s)',n.nspname,o.oprname,
        CASE WHEN o.oprleft=0 THEN 'NONE' ELSE o.oprleft::pg_catalog.regtype::text END,
        CASE WHEN o.oprright=0 THEN 'NONE' ELSE o.oprright::pg_catalog.regtype::text END),owner.rolname,
        jsonb_build_object('result',o.oprresult::pg_catalog.regtype::text,'function',o.oprcode::pg_catalog.regprocedure::text,
          'commutator',CASE WHEN o.oprcom=0 THEN NULL ELSE o.oprcom::pg_catalog.regoperator::text END,
          'negator',CASE WHEN o.oprnegate=0 THEN NULL ELSE o.oprnegate::pg_catalog.regoperator::text END,'merge',o.oprcanmerge,'hash',o.oprcanhash)
      FROM pg_catalog.pg_operator o JOIN pg_catalog.pg_namespace n ON n.oid=o.oprnamespace JOIN pg_catalog.pg_roles owner ON owner.oid=o.oprowner
      WHERE n.nspname<>'information_schema' AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\\'
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_operator'::pg_catalog.regclass AND d.objid=o.oid AND d.deptype='e')
      UNION ALL
      SELECT 'cast',pg_catalog.format('%s AS %s',c.castsource::pg_catalog.regtype::text,c.casttarget::pg_catalog.regtype::text),NULL,
        jsonb_build_object('context',c.castcontext::text,'method',c.castmethod::text,'function',CASE WHEN c.castfunc=0 THEN NULL ELSE c.castfunc::pg_catalog.regprocedure::text END)
      FROM pg_catalog.pg_cast c JOIN pg_catalog.pg_type source_type ON source_type.oid=c.castsource JOIN pg_catalog.pg_namespace source_ns ON source_ns.oid=source_type.typnamespace
      JOIN pg_catalog.pg_type target_type ON target_type.oid=c.casttarget JOIN pg_catalog.pg_namespace target_ns ON target_ns.oid=target_type.typnamespace
      LEFT JOIN pg_catalog.pg_proc cast_function ON cast_function.oid=NULLIF(c.castfunc,0) LEFT JOIN pg_catalog.pg_namespace function_ns ON function_ns.oid=cast_function.pronamespace
      WHERE (source_ns.nspname<>'information_schema' AND source_ns.nspname NOT LIKE 'pg\_%' ESCAPE '\\')
         OR (target_ns.nspname<>'information_schema' AND target_ns.nspname NOT LIKE 'pg\_%' ESCAPE '\\')
         OR (function_ns.nspname<>'information_schema' AND function_ns.nspname NOT LIKE 'pg\_%' ESCAPE '\\')
      UNION ALL
      SELECT 'foreign_server',s.srvname,o.rolname,jsonb_build_object('wrapper',f.fdwname,'type',s.srvtype,'version',s.srvversion,
        'option_names',COALESCE((SELECT jsonb_agg(opt.option_name ORDER BY opt.option_name) FROM pg_catalog.pg_options_to_table(s.srvoptions) opt),'[]'::jsonb))
      FROM pg_catalog.pg_foreign_server s JOIN pg_catalog.pg_roles o ON o.oid=s.srvowner JOIN pg_catalog.pg_foreign_data_wrapper f ON f.oid=s.srvfdw
      UNION ALL
      SELECT 'foreign_data_wrapper',f.fdwname,o.rolname,jsonb_build_object(
        'handler',CASE WHEN f.fdwhandler=0 THEN NULL ELSE f.fdwhandler::pg_catalog.regprocedure::text END,
        'validator',CASE WHEN f.fdwvalidator=0 THEN NULL ELSE f.fdwvalidator::pg_catalog.regprocedure::text END,
        'option_names',COALESCE((SELECT jsonb_agg(opt.option_name ORDER BY opt.option_name) FROM pg_catalog.pg_options_to_table(f.fdwoptions) opt),'[]'::jsonb))
      FROM pg_catalog.pg_foreign_data_wrapper f JOIN pg_catalog.pg_roles o ON o.oid=f.fdwowner
      WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_foreign_data_wrapper'::pg_catalog.regclass AND d.objid=f.oid AND d.deptype='e')
      UNION ALL
      SELECT 'language',l.lanname,o.rolname,jsonb_build_object('trusted',l.lanpltrusted,
        'handler',l.lanplcallfoid::pg_catalog.regprocedure::text,'inline',CASE WHEN l.laninline=0 THEN NULL ELSE l.laninline::pg_catalog.regprocedure::text END,
        'validator',CASE WHEN l.lanvalidator=0 THEN NULL ELSE l.lanvalidator::pg_catalog.regprocedure::text END)
      FROM pg_catalog.pg_language l JOIN pg_catalog.pg_roles o ON o.oid=l.lanowner
      WHERE l.lanname NOT IN ('internal','c','sql')
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_language'::pg_catalog.regclass AND d.objid=l.oid AND d.deptype='e')
      UNION ALL
      SELECT 'user_mapping',pg_catalog.format('%I:%s',m.srvname,COALESCE(m.usename,'PUBLIC')),NULL,
        jsonb_build_object('option_names',COALESCE((SELECT jsonb_agg(opt.option_name ORDER BY opt.option_name) FROM pg_catalog.pg_options_to_table(m.umoptions) opt),'[]'::jsonb))
      FROM pg_catalog.pg_user_mappings m
    ) x`);
    const [routines] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.schema,x.name,x.arguments),'[]'::jsonb) AS rows FROM (
      SELECT n.nspname AS schema,p.proname AS name,pg_catalog.pg_get_function_identity_arguments(p.oid) AS arguments,
        pg_catalog.pg_get_function_result(p.oid) AS result,o.rolname AS owner,p.prosecdef AS security_definer,
        p.provolatile::text AS volatility,p.proparallel::text AS parallel,p.proleakproof AS leakproof,p.proisstrict AS strict,
        p.proconfig AS config,p.prosrc AS body,l.lanname AS language,
        pg_catalog.pg_get_functiondef(p.oid) AS definition,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('role',COALESCE(g.rolname,'PUBLIC'),'privilege',a.privilege_type,'grantable',a.is_grantable)
          ORDER BY COALESCE(g.rolname,'PUBLIC'),a.privilege_type,a.is_grantable)
          FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
          LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantee),'[]'::jsonb) AS grants
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      JOIN pg_catalog.pg_roles o ON o.oid=p.proowner JOIN pg_catalog.pg_language l ON l.oid=p.prolang
      WHERE n.nspname IN ('app_rls','app_auth','app_public','app_ops')
    ) x`);
    const [securityRoutines] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.schema,x.name,x.arguments,x.kind),'[]'::jsonb) AS rows FROM (
      SELECT n.nspname AS schema,p.proname AS name,pg_catalog.pg_get_function_identity_arguments(p.oid) AS arguments,p.prokind::text AS kind,
        pg_catalog.pg_get_function_result(p.oid) AS result,o.rolname AS owner,p.prosecdef AS security_definer,
        p.provolatile::text AS volatility,p.proparallel::text AS parallel,p.proleakproof AS leakproof,p.proisstrict AS strict,
        p.proconfig AS config,p.prosrc AS body,l.lanname AS language,
        CASE WHEN p.prokind='a' THEN NULL ELSE pg_catalog.pg_get_functiondef(p.oid) END AS definition,
        CASE WHEN p.prokind='a' THEN pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.jsonb_build_object(
          'kind',a.aggkind,'direct_args',a.aggnumdirectargs,'transition',a.aggtransfn::pg_catalog.regprocedure::text,
          'final',a.aggfinalfn::pg_catalog.regprocedure::text,'combine',a.aggcombinefn::pg_catalog.regprocedure::text,
          'serial',a.aggserialfn::pg_catalog.regprocedure::text,'deserial',a.aggdeserialfn::pg_catalog.regprocedure::text,
          'moving_transition',a.aggmtransfn::pg_catalog.regprocedure::text,'moving_inverse',a.aggminvtransfn::pg_catalog.regprocedure::text,
          'moving_final',a.aggmfinalfn::pg_catalog.regprocedure::text,'final_extra',a.aggfinalextra,'moving_final_extra',a.aggmfinalextra,
          'final_modify',a.aggfinalmodify::text,'moving_final_modify',a.aggmfinalmodify::text,'sort_operator',a.aggsortop::pg_catalog.regoperator::text,
          'transition_type',a.aggtranstype::pg_catalog.regtype::text,'transition_space',a.aggtransspace,
          'moving_transition_type',a.aggmtranstype::pg_catalog.regtype::text,'moving_transition_space',a.aggmtransspace,
          'initial_value',a.agginitval,'moving_initial_value',a.aggminitval)::text,'UTF8')),'hex') END AS aggregate_state_sha256,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('role',COALESCE(g.rolname,'PUBLIC'),'grantor',grantor.rolname,'privilege',a.privilege_type,'grantable',a.is_grantable)
          ORDER BY COALESCE(g.rolname,'PUBLIC'),grantor.rolname,a.privilege_type,a.is_grantable)
          FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
          LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantee JOIN pg_catalog.pg_roles grantor ON grantor.oid=a.grantor),'[]'::jsonb) AS grants
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      JOIN pg_catalog.pg_roles o ON o.oid=p.proowner JOIN pg_catalog.pg_language l ON l.oid=p.prolang
      LEFT JOIN pg_catalog.pg_aggregate a ON a.aggfnoid=p.oid
      WHERE n.nspname<>'information_schema' AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\\'
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_proc'::pg_catalog.regclass
          AND d.objid=p.oid AND d.deptype='e')
    ) x`);
    const [tables] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.name),'[]'::jsonb) AS rows FROM (
      SELECT c.relname AS name,c.relkind::text AS kind,c.relrowsecurity AS rls,c.relforcerowsecurity AS forced,
        o.rolname AS owner,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('name',a.attname,'type',pg_catalog.format_type(a.atttypid,a.atttypmod),'notNull',a.attnotnull,
          'identity',a.attidentity::text,'generated',a.attgenerated::text,'default',pg_catalog.pg_get_expr(d.adbin,d.adrelid),
          'enumLabels',COALESCE((SELECT jsonb_agg(e.enumlabel ORDER BY e.enumsortorder)
            FROM pg_catalog.pg_enum e WHERE e.enumtypid IN
              (a.atttypid,(SELECT t.typelem FROM pg_catalog.pg_type t WHERE t.oid=a.atttypid))),'[]'::jsonb))
          ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
          LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
          WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),'[]'::jsonb) AS columns,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('name',k.conname,'definition',pg_catalog.pg_get_constraintdef(k.oid),'validated',k.convalidated)
          ORDER BY k.conname) FROM pg_catalog.pg_constraint k WHERE k.conrelid=c.oid),'[]'::jsonb) AS constraints,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('role',COALESCE(g.rolname,'PUBLIC'),'privilege',acl.privilege_type,'grantable',acl.is_grantable)
          ORDER BY COALESCE(g.rolname,'PUBLIC'),acl.privilege_type,acl.is_grantable)
          FROM pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) acl
          LEFT JOIN pg_catalog.pg_roles g ON g.oid=acl.grantee),'[]'::jsonb) AS grants,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('column',a.attname,'role',COALESCE(g.rolname,'PUBLIC'),'privilege',acl.privilege_type,'grantable',acl.is_grantable)
          ORDER BY a.attname,COALESCE(g.rolname,'PUBLIC'),acl.privilege_type,acl.is_grantable)
          FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
          LEFT JOIN pg_catalog.pg_roles g ON g.oid=acl.grantee
          WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),'[]'::jsonb) AS column_grants
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      JOIN pg_catalog.pg_roles o ON o.oid=c.relowner WHERE n.nspname='public' AND c.relkind IN ('r','p')
    ) x`);
    const [securityTables] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.schema,x.name),'[]'::jsonb) AS rows FROM (
      SELECT n.nspname AS schema,c.relname AS name,c.relkind::text AS kind,c.relrowsecurity AS rls,c.relforcerowsecurity AS forced,
        o.rolname AS owner,CASE WHEN c.relkind IN ('v','m') THEN pg_catalog.pg_get_viewdef(c.oid,false) END AS view_definition,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('name',opt.option_name,'value',opt.option_value) ORDER BY opt.option_name)
          FROM pg_catalog.pg_options_to_table(c.reloptions) opt WHERE opt.option_name IN ('security_barrier','security_invoker','check_option')),'[]'::jsonb) AS view_security_options,
        CASE WHEN c.relkind='p' THEN pg_catalog.pg_get_partkeydef(c.oid) END AS partition_key,
        CASE WHEN c.relispartition THEN pg_catalog.pg_get_expr(c.relpartbound,c.oid,false) END AS partition_bound,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('name',a.attname,'type',pg_catalog.format_type(a.atttypid,a.atttypmod),'notNull',a.attnotnull,
          'identity',a.attidentity::text,'generated',a.attgenerated::text,'default',pg_catalog.pg_get_expr(d.adbin,d.adrelid),
          'collation',CASE WHEN a.attcollation=0 THEN NULL ELSE a.attcollation::pg_catalog.regcollation::text END,
          'enumLabels',COALESCE((SELECT jsonb_agg(e.enumlabel ORDER BY e.enumsortorder) FROM pg_catalog.pg_enum e
            WHERE e.enumtypid IN (a.atttypid,(SELECT t.typelem FROM pg_catalog.pg_type t WHERE t.oid=a.atttypid))),'[]'::jsonb)) ORDER BY a.attnum)
          FROM pg_catalog.pg_attribute a LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
          WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),'[]'::jsonb) AS columns,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('name',k.conname,'definition',pg_catalog.pg_get_constraintdef(k.oid),'validated',k.convalidated,
          'local',k.conislocal,'inheritance_count',k.coninhcount,'no_inherit',k.connoinherit,
          'parent_identity',CASE WHEN parent_oid.oid IS NOT NULL THEN pg_catalog.format('%I.%I.%I',pno.nspname,pco.relname,parent_oid.conname) ELSE parent_inherited.identity END) ORDER BY k.conname)
          FROM pg_catalog.pg_constraint k LEFT JOIN pg_catalog.pg_constraint parent_oid ON parent_oid.oid=NULLIF(k.conparentid,0)
          LEFT JOIN pg_catalog.pg_class pco ON pco.oid=parent_oid.conrelid LEFT JOIN pg_catalog.pg_namespace pno ON pno.oid=pco.relnamespace
          LEFT JOIN LATERAL (SELECT pg_catalog.format('%I.%I.%I',parent_ns.nspname,parent_rel.relname,parent.conname) AS identity FROM pg_catalog.pg_inherits i
            JOIN pg_catalog.pg_constraint parent ON parent.conrelid=i.inhparent AND parent.conname=k.conname AND parent.contype=k.contype
            JOIN pg_catalog.pg_class parent_rel ON parent_rel.oid=parent.conrelid JOIN pg_catalog.pg_namespace parent_ns ON parent_ns.oid=parent_rel.relnamespace
            WHERE i.inhrelid=k.conrelid ORDER BY i.inhseqno LIMIT 1) parent_inherited ON parent_oid.oid IS NULL
          WHERE k.conrelid=c.oid),'[]'::jsonb) AS constraints,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('role',COALESCE(g.rolname,'PUBLIC'),'grantor',grantor.rolname,'privilege',acl.privilege_type,'grantable',acl.is_grantable)
          ORDER BY COALESCE(g.rolname,'PUBLIC'),grantor.rolname,acl.privilege_type,acl.is_grantable) FROM pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) acl
          LEFT JOIN pg_catalog.pg_roles g ON g.oid=acl.grantee JOIN pg_catalog.pg_roles grantor ON grantor.oid=acl.grantor),'[]'::jsonb) AS grants,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('column',a.attname,'role',COALESCE(g.rolname,'PUBLIC'),'grantor',grantor.rolname,'privilege',acl.privilege_type,'grantable',acl.is_grantable)
          ORDER BY a.attname,COALESCE(g.rolname,'PUBLIC'),grantor.rolname,acl.privilege_type,acl.is_grantable) FROM pg_catalog.pg_attribute a
          CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl LEFT JOIN pg_catalog.pg_roles g ON g.oid=acl.grantee JOIN pg_catalog.pg_roles grantor ON grantor.oid=acl.grantor
          WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),'[]'::jsonb) AS column_grants
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_roles o ON o.oid=c.relowner
      WHERE n.nspname<>'information_schema' AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\\' AND c.relkind IN ('r','p','v','m','f')
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_class'::pg_catalog.regclass AND d.objid=c.oid AND d.deptype='e')
    ) x`);
    const [securityTriggers] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.schema,x.relation,x.name),'[]'::jsonb) AS rows FROM (
      SELECT n.nspname AS schema,c.relname AS relation,t.tgname AS name,t.tgenabled::text AS enabled,
        pg_catalog.format('%I.%I(%s)',fnns.nspname,p.proname,pg_catalog.pg_get_function_identity_arguments(p.oid)) AS function,
        pg_catalog.pg_get_triggerdef(t.oid,false) AS definition
      FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
      JOIN pg_catalog.pg_namespace fnns ON fnns.oid=p.pronamespace
      WHERE NOT t.tgisinternal AND n.nspname<>'information_schema' AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\\'
        AND c.relkind IN ('r','p','v','m','f')
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_class'::pg_catalog.regclass AND d.objid=c.oid AND d.deptype='e')
    ) x`);
    const [securityRules] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.schema,x.relation,x.name),'[]'::jsonb) AS rows FROM (
      SELECT n.nspname AS schema,c.relname AS relation,r.rulename AS name,r.ev_type::text AS event,r.ev_enabled::text AS enabled,
        pg_catalog.pg_get_ruledef(r.oid,false) AS definition
      FROM pg_catalog.pg_rewrite r JOIN pg_catalog.pg_class c ON c.oid=r.ev_class JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE r.rulename<>'_RETURN' AND c.relkind IN ('r','p','v','m','f') AND n.nspname<>'information_schema' AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_class'::pg_catalog.regclass AND d.objid=c.oid AND d.deptype='e')
    ) x`);
    const [securityEventTriggers] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.name),'[]'::jsonb) AS rows FROM (
      SELECT e.evtname AS name,o.rolname AS owner,e.evtevent AS event,e.evtenabled::text AS enabled,
        CASE WHEN e.evttags IS NULL THEN NULL ELSE COALESCE((SELECT jsonb_agg(tag ORDER BY tag) FROM unnest(e.evttags) tag),'[]'::jsonb) END AS tags,
        pg_catalog.format('%I.%I()',n.nspname,p.proname) AS function
      FROM pg_catalog.pg_event_trigger e JOIN pg_catalog.pg_roles o ON o.oid=e.evtowner
      JOIN pg_catalog.pg_proc p ON p.oid=e.evtfoid JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_event_trigger'::pg_catalog.regclass AND d.objid=e.oid AND d.deptype='e')
    ) x`);
    const [policies] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x."table",x.name),'[]'::jsonb) AS rows FROM (
      SELECT c.relname AS "table",p.polname AS name,p.polpermissive AS permissive,p.polcmd::text AS command,
        ARRAY(SELECT COALESCE(r.rolname,'PUBLIC') FROM unnest(p.polroles) i LEFT JOIN pg_catalog.pg_roles r ON r.oid=i ORDER BY COALESCE(r.rolname,'PUBLIC')) AS roles,
        pg_catalog.pg_get_expr(p.polqual,p.polrelid) AS "using",pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid) AS "check"
      FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid=p.polrelid
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
    ) x`);
    const [securityPolicies] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.schema,x."table",x.name),'[]'::jsonb) AS rows FROM (
      SELECT n.nspname AS schema,c.relname AS "table",p.polname AS name,p.polpermissive AS permissive,p.polcmd::text AS command,
        ARRAY(SELECT COALESCE(r.rolname,'PUBLIC') FROM unnest(p.polroles) i LEFT JOIN pg_catalog.pg_roles r ON r.oid=i ORDER BY COALESCE(r.rolname,'PUBLIC')) AS roles,
        pg_catalog.pg_get_expr(p.polqual,p.polrelid) AS "using",pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid) AS "check"
      FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid=p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname<>'information_schema' AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\\'
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_policy'::pg_catalog.regclass AND d.objid=p.oid AND d.deptype='e')
    ) x`);
    const [schemas] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.name),'[]'::jsonb) AS rows FROM (
      SELECT n.nspname AS name,o.rolname AS owner,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('role',COALESCE(g.rolname,'PUBLIC'),'privilege',a.privilege_type,'grantable',a.is_grantable)
          ORDER BY COALESCE(g.rolname,'PUBLIC'),a.privilege_type,a.is_grantable)
          FROM pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
          LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantee),'[]'::jsonb) AS grants
      FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles o ON o.oid=n.nspowner
      WHERE n.nspname IN ('public','app_rls','app_auth','app_public','app_ops')
    ) x`);
    const [securitySchemas] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.name),'[]'::jsonb) AS rows FROM (
      SELECT n.nspname AS name,o.rolname AS owner,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('role',COALESCE(g.rolname,'PUBLIC'),'grantor',grantor.rolname,'privilege',a.privilege_type,'grantable',a.is_grantable)
          ORDER BY COALESCE(g.rolname,'PUBLIC'),grantor.rolname,a.privilege_type,a.is_grantable)
          FROM pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
          LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantee JOIN pg_catalog.pg_roles grantor ON grantor.oid=a.grantor),'[]'::jsonb) AS grants
      FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles o ON o.oid=n.nspowner
      WHERE n.nspname<>'information_schema' AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\\'
    ) x`);
    const [roles] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.name),'[]'::jsonb) AS rows FROM (
      SELECT r.rolname AS name,r.rolcanlogin AS login,r.rolsuper AS superuser,r.rolinherit AS inherit,
        r.rolcreaterole AS create_role,r.rolcreatedb AS create_database,r.rolreplication AS replication,r.rolbypassrls AS bypass_rls,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('role',parent.rolname,'admin',m.admin_option,'inherit',m.inherit_option,'set',m.set_option)
          ORDER BY parent.rolname,m.admin_option,m.inherit_option,m.set_option)
          FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles parent ON parent.oid=m.roleid WHERE m.member=r.oid),'[]'::jsonb) AS memberships,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('member',child.rolname,'admin',m.admin_option,'inherit',m.inherit_option,'set',m.set_option)
          ORDER BY child.rolname,m.admin_option,m.inherit_option,m.set_option)
          FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles child ON child.oid=m.member WHERE m.roleid=r.oid),'[]'::jsonb) AS members
      FROM pg_catalog.pg_roles r WHERE r.rolname LIKE 'mscqr\\_prd\\_rls\\_phase2\\_%' ESCAPE '\\'
        OR r.rolname='mscqr_prod_rls_canary_read'
    ) x`);
    const [securityRoles] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.name),'[]'::jsonb) AS rows FROM (
      SELECT r.rolname AS name,r.rolcanlogin AS login,r.rolvaliduntil::text AS valid_until,r.rolsuper AS superuser,r.rolinherit AS inherit,
        r.rolcreaterole AS create_role,r.rolcreatedb AS create_database,r.rolreplication AS replication,r.rolbypassrls AS bypass_rls,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('role',parent.rolname,'grantor',grantor.rolname,'admin',m.admin_option,'inherit',m.inherit_option,'set',m.set_option)
          ORDER BY parent.rolname,grantor.rolname,m.admin_option,m.inherit_option,m.set_option)
          FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles parent ON parent.oid=m.roleid JOIN pg_catalog.pg_roles grantor ON grantor.oid=m.grantor
          WHERE m.member=r.oid),'[]'::jsonb) AS memberships,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('member',child.rolname,'grantor',grantor.rolname,'admin',m.admin_option,'inherit',m.inherit_option,'set',m.set_option)
          ORDER BY child.rolname,grantor.rolname,m.admin_option,m.inherit_option,m.set_option)
          FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles child ON child.oid=m.member JOIN pg_catalog.pg_roles grantor ON grantor.oid=m.grantor
          WHERE m.roleid=r.oid),'[]'::jsonb) AS members
      FROM pg_catalog.pg_roles r WHERE r.rolname !~ '^pg\\_' AND r.rolname NOT IN
        ('rdsadmin','rds_superuser','rds_password','rds_iam','rds_replication','rds_ad','rds_directory_service_role','rds_reserved','rdstopmgr')
    ) x`);
    const [roleMetadata] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.name),'[]'::jsonb) AS rows FROM (
      SELECT r.rolname AS name,pg_catalog.shobj_description(r.oid,'pg_authid') IS NOT NULL AS comment_present,
        pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(COALESCE(pg_catalog.shobj_description(r.oid,'pg_authid'),''),'UTF8')),'hex') AS comment_sha256,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('database',COALESCE(d.datname,'*'),'settings',s.safe_settings) ORDER BY COALESCE(d.datname,'*'))
          FROM pg_catalog.pg_db_role_setting rs LEFT JOIN pg_catalog.pg_database d ON d.oid=rs.setdatabase
          CROSS JOIN LATERAL (SELECT COALESCE(jsonb_agg(setting ORDER BY setting),'[]'::jsonb) AS safe_settings
            FROM unnest(rs.setconfig) setting WHERE split_part(setting,'=',1) IN
              ('statement_timeout','lock_timeout','idle_in_transaction_session_timeout','search_path','default_transaction_read_only','row_security')) s
          WHERE rs.setrole=r.oid),'[]'::jsonb) AS settings,
        EXISTS(SELECT 1 FROM pg_catalog.pg_db_role_setting rs CROSS JOIN LATERAL unnest(rs.setconfig) setting
          WHERE rs.setrole=r.oid AND split_part(setting,'=',1) NOT IN
            ('statement_timeout','lock_timeout','idle_in_transaction_session_timeout','search_path','default_transaction_read_only','row_security')) AS unsupported_settings
      FROM pg_catalog.pg_roles r WHERE r.rolname !~ '^pg\\_' AND r.rolname NOT IN
        ('rdsadmin','rds_superuser','rds_password','rds_iam','rds_replication','rds_ad','rds_directory_service_role','rds_reserved','rdstopmgr')
    ) x`);
    const [databases] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.database,x.role,x.grantor,x.privilege,x.grantable),'[]'::jsonb) AS rows FROM (
      SELECT d.datname AS database,o.rolname AS owner,COALESCE(g.rolname,'PUBLIC') AS role,grantor.rolname AS grantor,a.privilege_type AS privilege,a.is_grantable AS grantable
      FROM pg_catalog.pg_database d JOIN pg_catalog.pg_roles o ON o.oid=d.datdba
      CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(d.datacl,pg_catalog.acldefault('d',d.datdba))) a
      LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantee JOIN pg_catalog.pg_roles grantor ON grantor.oid=a.grantor WHERE d.datname=current_database()
    ) x`);
    const [defaults] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.owner,x.schema,x.object_type,x.role,x.grantor,x.privilege,x.grantable),'[]'::jsonb) AS rows FROM (
      SELECT o.rolname AS owner,COALESCE(n.nspname,'*') AS schema,d.defaclobjtype::text AS object_type,
        COALESCE(g.rolname,'PUBLIC') AS role,grantor.rolname AS grantor,a.privilege_type AS privilege,a.is_grantable AS grantable
      FROM pg_catalog.pg_default_acl d JOIN pg_catalog.pg_roles o ON o.oid=d.defaclrole
      LEFT JOIN pg_catalog.pg_namespace n ON n.oid=d.defaclnamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) a LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantee JOIN pg_catalog.pg_roles grantor ON grantor.oid=a.grantor
    ) x`);
    const [types] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.schema,x.name),'[]'::jsonb) AS rows FROM (
      SELECT n.nspname AS schema,t.typname AS name,t.typtype::text AS kind,o.rolname AS owner,t.typcategory::text AS category,
        t.typnotnull AS not_null,CASE WHEN t.typbasetype=0 THEN NULL ELSE pg_catalog.format_type(t.typbasetype,t.typtypmod) END AS base_type,
        CASE WHEN t.typcollation=0 THEN NULL ELSE t.typcollation::pg_catalog.regcollation::text END AS collation,
        t.typdefault AS default_value,CASE WHEN t.typdefaultbin IS NULL THEN NULL ELSE pg_catalog.pg_get_expr(t.typdefaultbin,0,false) END AS default_expression,
        COALESCE((SELECT jsonb_agg(e.enumlabel ORDER BY e.enumsortorder) FROM pg_catalog.pg_enum e WHERE e.enumtypid=t.oid),'[]'::jsonb) AS enum_labels,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('name',k.conname,'definition',pg_catalog.pg_get_constraintdef(k.oid),'validated',k.convalidated,
          'deferrable',k.condeferrable,'initially_deferred',k.condeferred) ORDER BY k.conname) FROM pg_catalog.pg_constraint k WHERE k.contypid=t.oid),'[]'::jsonb) AS constraints,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('role',COALESCE(g.rolname,'PUBLIC'),'grantor',grantor.rolname,'privilege',a.privilege_type,'grantable',a.is_grantable)
          ORDER BY COALESCE(g.rolname,'PUBLIC'),grantor.rolname,a.privilege_type,a.is_grantable)
          FROM pg_catalog.aclexplode(COALESCE(t.typacl,pg_catalog.acldefault('T',t.typowner))) a LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantee JOIN pg_catalog.pg_roles grantor ON grantor.oid=a.grantor),'[]'::jsonb) AS grants
      FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace JOIN pg_catalog.pg_roles o ON o.oid=t.typowner
      WHERE n.nspname<>'information_schema' AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\\' AND t.typtype<>'p' AND t.typcategory<>'A'
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_type'::pg_catalog.regclass AND d.objid=t.oid AND d.deptype='e')
    ) x`);
    const [sequences] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.schema,x.name),'[]'::jsonb) AS rows FROM (
      SELECT n.nspname AS schema,c.relname AS name,o.rolname AS owner,s.seqtypid::pg_catalog.regtype::text AS data_type,
        s.seqstart::text AS start_value,s.seqincrement::text AS increment_by,s.seqmax::text AS maximum,s.seqmin::text AS minimum,s.seqcache::text AS cache_size,s.seqcycle AS cycle,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('role',COALESCE(g.rolname,'PUBLIC'),'grantor',grantor.rolname,'privilege',a.privilege_type,'grantable',a.is_grantable)
          ORDER BY COALESCE(g.rolname,'PUBLIC'),grantor.rolname,a.privilege_type,a.is_grantable)
          FROM pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('S',c.relowner))) a LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantee JOIN pg_catalog.pg_roles grantor ON grantor.oid=a.grantor),'[]'::jsonb) AS grants
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_roles o ON o.oid=c.relowner
      JOIN pg_catalog.pg_sequence s ON s.seqrelid=c.oid
      WHERE c.relkind='S' AND n.nspname<>'information_schema' AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\\'
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_class'::pg_catalog.regclass AND d.objid=c.oid AND d.deptype='e')
    ) x`);
    const [operatorCapabilities] = await tx.$queryRawUnsafe(`WITH RECURSIVE membership_closure(member,roleid) AS (
      SELECT m.member,m.roleid FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles member ON member.oid=m.member
      WHERE m.inherit_option AND member.rolinherit
      UNION SELECT c.member,m.roleid FROM membership_closure c JOIN pg_catalog.pg_roles intermediate ON intermediate.oid=c.roleid AND intermediate.rolinherit
        JOIN pg_catalog.pg_auth_members m ON m.member=c.roleid WHERE m.inherit_option
    ) SELECT COALESCE(jsonb_agg(x ORDER BY x.name),'[]'::jsonb) AS rows FROM (
      SELECT r.rolname AS name,r.rolcanlogin AS login,r.rolvaliduntil::text AS valid_until,r.rolsuper AS superuser,r.rolinherit AS inherit,r.rolcreaterole AS create_role,
        r.rolcreatedb AS create_database,r.rolreplication AS replication,r.rolbypassrls AS bypass_rls,
        pg_catalog.has_database_privilege(r.oid,current_database(),'CONNECT') AS database_connect,
        pg_catalog.has_database_privilege(r.oid,current_database(),'CREATE') AS database_create,
        pg_catalog.has_database_privilege(r.oid,current_database(),'TEMPORARY') AS database_temporary,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('role',parent.rolname,'grantor',grantor.rolname,'admin',m.admin_option,'inherit',m.inherit_option,'set',m.set_option)
          ORDER BY parent.rolname,grantor.rolname,m.admin_option,m.inherit_option,m.set_option) FROM pg_catalog.pg_auth_members m
          JOIN pg_catalog.pg_roles parent ON parent.oid=m.roleid JOIN pg_catalog.pg_roles grantor ON grantor.oid=m.grantor WHERE m.member=r.oid),'[]'::jsonb) AS memberships,
        COALESCE((SELECT jsonb_agg(parent.rolname ORDER BY parent.rolname) FROM membership_closure c
          JOIN pg_catalog.pg_roles parent ON parent.oid=c.roleid WHERE c.member=r.oid),'[]'::jsonb) AS membership_closure
      FROM pg_catalog.pg_roles r WHERE r.rolname='mscqr_prod_admin'
    ) x`);
    return { identity, routines: routines.rows, securityRoutines: securityRoutines.rows, securityExtensions: securityExtensions.rows, securityBindings: securityBindings.rows, tables: tables.rows, securityTables: securityTables.rows, policies: policies.rows, securityPolicies: securityPolicies.rows, schemas: schemas.rows,
      securitySchemas: securitySchemas.rows, securityTriggers: securityTriggers.rows, securityRules: securityRules.rows, securityEventTriggers: securityEventTriggers.rows,
      roles: roles.rows, securityRoles: securityRoles.rows, roleMetadata: roleMetadata.rows, databases: databases.rows,
      defaults: defaults.rows, types: types.rows, sequences: sequences.rows, operatorCapabilities: operatorCapabilities.rows };
}

export async function collectAppOnlyDatabaseCatalogue(client) {
  return client.$transaction(async (tx) => {
    await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
    return collectAppOnlyDatabaseCatalogueRows(tx, (identity) => {
      if (!identity || identity.role !== "mscqr_prod_rls_canary_read" || identity.session_role !== identity.role
      || identity.database !== "mscqr_production_rls_green_phase2" || Math.trunc(Number(identity.server_version_num) / 10000) !== 18
      || identity.read_only !== "on"
      || identity.default_read_only !== "on"
      || ["rolsuper", "rolinherit", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls", "memberships", "write_privileges", "schema_write", "database_write"].some((key) => identity[key] !== false)) {
        throw new Error("Verifier database identity is not the restricted read-only contract");
      }
    });
  }, { maxWait: 5000, timeout: 30000 });
}

// Local evaluation only. Expectations must be derived from the authenticated
// canonical candidate requirements; this is not an artifact authentication API.
export function evaluateAppOnlyDatabaseCatalogue(observed, required) {
  const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const result = Object.fromEntries(["DATABASE_SCHEMA", "RLS_FUNCTIONS", "RLS_POLICIES", "RLS_GRANTS", "RLS_FORCE_STATUS", "GENERATED_RLS_CONTRACT"].map((key) => [key, "UNPROVEN"]));
  if (!required || !required.contractSha256 || !Array.isArray(required.routines)
    || !Array.isArray(required.tables) || !Array.isArray(required.policies) || !Array.isArray(required.schemas)
    || !Array.isArray(required.roles) || !required.roles.length
    || !required.routines.length || !required.tables.length || !required.policies.length || !required.schemas.length) return result;
  const unique = (rows, key) => Array.isArray(rows) && new Set(rows.map(key)).size === rows.length;
  if (!unique(observed?.routines, (row) => `${row.schema}.${row.name}(${row.arguments})`)
    || !unique(observed?.tables, (row) => row.name) || !unique(observed?.schemas, (row) => row.name)
    || !unique(observed?.roles, (row) => row.name) || !unique(observed?.policies, (row) => `${row.table}.${row.name}`)) return result;
  const mark = (value) => value ? "COMPATIBLE" : "INCOMPATIBLE";
  const routine = (r) => observed.routines.find((o) => o.schema === r.schema && o.name === r.name && o.arguments === r.arguments);
  const table = (r) => observed.tables.find((o) => o.name === r.name);
  result.RLS_FUNCTIONS = mark(required.routines.every((r) => {
    const o = routine(r);
    return o && ["result", "owner", "security_definer", "volatility", "parallel", "leakproof", "strict", "config", "body", "language", "definition"].every((key) => Object.hasOwn(r,key) && equal(o[key],r[key]));
  }));
  result.RLS_GRANTS = mark(required.routines.every((r) => routine(r) && Array.isArray(r.grants) && equal(routine(r).grants, r.grants))
    && required.tables.every((r) => table(r) && ["grants", "column_grants"].every((key) => Array.isArray(r[key]) && equal(table(r)[key], r[key])))
    && required.schemas.every((r) => Array.isArray(r.grants) && equal(observed.schemas.find((o) => o.name === r.name)?.grants, r.grants))
    && required.roles.every((r) => equal(observed.roles.find((o) => o.name === r.name), r)));
  result.RLS_POLICIES = mark(required.policies.every((r) => {
    const o = observed.policies.find((p) => p.table === r.table && p.name === r.name);
    return o && ["permissive", "command", "roles", "using", "check"].every((key) => Object.hasOwn(r,key) && equal(o[key],r[key]));
  }) && observed.policies.filter((o) => required.tables.some((t) => t.name === o.table)).every((o) => required.policies.some((r) => r.table === o.table && r.name === o.name)));
  result.DATABASE_SCHEMA = mark(required.tables.every((r) => {
    const o = table(r);
    return o && Object.hasOwn(r,"owner") && o.owner === r.owner && o.kind === r.kind
      && ["columns", "constraints"].every((key) => Array.isArray(r[key]) && equal(o[key],r[key]));
  }) && required.schemas.every((r) => typeof r.owner === "string" && observed.schemas.find((o) => o.name === r.name)?.owner === r.owner));
  result.RLS_FORCE_STATUS = mark(required.tables.every((r) => typeof r.rls === "boolean" && typeof r.forced === "boolean"
    && table(r)?.rls === r.rls && table(r)?.forced === r.forced));
  result.GENERATED_RLS_CONTRACT = Object.entries(result).filter(([key]) => key !== "GENERATED_RLS_CONTRACT").every(([, value]) => value === "COMPATIBLE") ? "COMPATIBLE" : "UNPROVEN";
  return result;
}
