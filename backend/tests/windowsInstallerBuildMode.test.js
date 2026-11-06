const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
(async()=>{
  const packaging=path.resolve(__dirname,'../local-print-agent/packaging');
  const {windowsBuildMode}=await import(require('node:url').pathToFileURL(path.join(packaging,'windows-build-mode.mjs')));
  const approved='https://isolated.example.invalid';
  const credentialed=new URL(approved);credentialed.username='fixture';credentialed.password=require('node:crypto').randomUUID();
  const candidate=value=>windowsBuildMode(['--mode=signed-candidate'],{MSCQR_MAINTENANCE_API_ORIGIN:value,MSCQR_APPROVED_MAINTENANCE_API_ORIGIN:approved});
  for(const value of [undefined,'','http://isolated.example.invalid','invalid',credentialed.href,'https://isolated.example.invalid/api','https://other.invalid','https://isolated.example.invalid?','https://isolated.example.invalid#','https://isolated.example.invalid/a/..','https://isolated.example.invalid\\'])assert.throws(()=>candidate(value));
  assert.equal(candidate(approved).maintenanceOrigin,approved);
  assert.throws(()=>windowsBuildMode(['--mode=signed-candidate'],{MSCQR_MAINTENANCE_API_ORIGIN:approved}));
  assert.equal(windowsBuildMode(['--mode=development'],{}).productionEligible,false);
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'mscqr-build-mode-'));
  try {
    const backend=path.join(root,'backend');
    fs.mkdirSync(backend);
    // Run the actual documented package command/builder. Only npm/PKG/native
    // self-test are substituted; no production credential or signing is used.
    fs.cpSync(path.resolve(__dirname,'../local-print-agent/install'),path.join(backend,'local-print-agent/install'),{recursive:true});
    fs.cpSync(packaging,path.join(backend,'local-print-agent/packaging'),{recursive:true});
    fs.cpSync(path.resolve(__dirname,'../../documents/legal/connector'),path.join(root,'documents/legal/connector'),{recursive:true});
    fs.mkdirSync(path.join(backend,'src/local-print-agent'),{recursive:true});
    fs.copyFileSync(path.resolve(__dirname,'../src/local-print-agent/version.ts'),path.join(backend,'src/local-print-agent/version.ts'));
    fs.mkdirSync(path.join(backend,'dist/local-print-agent'),{recursive:true});fs.writeFileSync(path.join(backend,'dist/local-print-agent/index.js'),'fixture');
    fs.mkdirSync(path.join(backend,'node_modules/.bin'),{recursive:true});
    fs.writeFileSync(path.join(backend,'node_modules/.bin',process.platform==='win32'?'pkg.cmd':'pkg'),'fixture');
    const preload=path.join(root,'toolchain.cjs');
    fs.writeFileSync(preload,`const fs=require('fs');require('child_process').spawnSync=(cmd,args,options)=>{if(args.includes('--output'))fs.writeFileSync(args[args.indexOf('--output')+1]+'.exe',Buffer.alloc(1000001));return {status:0,stdout:JSON.stringify({ok:true,buildVersion:options?.env?.PRINT_AGENT_BUILD_VERSION})};};require('module').syncBuiltinESMExports();`);
    const script=JSON.parse(fs.readFileSync(path.resolve(__dirname,'../package.json'))).scripts['connector:windows:build-installer'];
    assert(script.endsWith('--mode=development'));
    const result=spawnSync(process.execPath,['--require',preload,...script.split(' ').slice(1)],{cwd:backend,encoding:'utf8',env:{...process.env,WEB_APP_BASE_URL:'http://127.0.0.1:1',MSCQR_MAINTENANCE_API_ORIGIN:'',MSCQR_APPROVED_MAINTENANCE_API_ORIGIN:'',INNO_SETUP_COMPILER_PATH:path.join(root,'unavailable.exe')}});
    assert.equal(result.status,0,result.stderr);
    const stage=path.join(backend,'.connector-build/windows-installer-development');
    const metadata=JSON.parse(fs.readFileSync(path.join(stage,'staging/installer-build.json')));
    assert.equal(metadata.productionEligible,false);
    assert.equal(metadata.maintenanceOrigin,'MSCQR_DEVELOPMENT_UPGRADES_DISABLED');
    const iss=fs.readFileSync(path.join(stage,`MSCQR-Connector-${metadata.version}.iss`),'utf8');
    assert(iss.startsWith('#define MSCQR_DEVELOPMENT_FIXTURE'));
    assert(iss.includes('-DEVELOPMENT-unsigned'));
    assert(iss.includes('#error Development fixtures cannot enter signed release compilation.'));
    assert(!fs.existsSync(path.join(backend,'local-print-agent/releases')),'development scaffold must not write publication tree');
    const incompatible=spawnSync(process.execPath,['--require',preload,'local-print-agent/packaging/build-windows-installer.mjs','--mode=signed-candidate'],{cwd:backend,encoding:'utf8',env:{...process.env,CONNECTOR_RELEASE_VERSION:'0.0.1',WEB_APP_BASE_URL:'http://127.0.0.1:1',MSCQR_MAINTENANCE_API_ORIGIN:approved,MSCQR_APPROVED_MAINTENANCE_API_ORIGIN:approved}});
    assert.notEqual(incompatible.status,0);assert.match(incompatible.stderr,/source connector buildVersion/,'candidate metadata must match the compiled source version');
    const publish=spawnSync(process.execPath,[path.join(packaging,'publish-windows-connector-release.mjs')],{encoding:'utf8',env:{...process.env,WINDOWS_CONNECTOR_SIGNED_INSTALLER_PATH:path.join(stage,'output','DEVELOPMENT.exe')}});
    assert.notEqual(publish.status,0);assert.match(publish.stderr,/development artifacts are forbidden/);
    console.log('PASS Windows build modes: documented development scaffold, candidate origin validation, publication rejection');
  }finally{fs.rmSync(root,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exitCode=1;});
