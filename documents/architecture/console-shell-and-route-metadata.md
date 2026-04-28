# Console Shell and Route Metadata

This console now uses a single route metadata source for:

- canonical admin route paths
- legacy route aliases and redirects
- role-based navigation labels
- breadcrumb labels
- contextual help routing

Why this exists:

- user-facing labels should not drift between navigation, dashboards, help, and redirects
- role-specific navigation should be defined once, not hardcoded inside the shell
- renamed surfaces such as `Code Requests`, `Scan Activity`, `Audit History`, and `Incident Response` need stable canonical URLs while old URLs still resolve safely

Current expectations:

- add new admin-facing pages to `src/app/route-metadata.ts`
- use canonical routes in navigation, quick actions, notifications, and help links
- keep legacy paths only as redirects in `src/App.tsx`
- keep page-level copy simple; advanced workflow details belong in contextual help or advanced sections, not the main page header
