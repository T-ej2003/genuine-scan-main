# Dashboard snapshot query profile

PostgreSQL 18 profiling isolated `app_rls.dashboard_snapshot_data(...)` to the
`InventoryStatusRollup` aggregate. The table scan itself completed in 3.5 ms.
The clean-room fixture loaded its rows after indexes existed but did not run
`ANALYZE`, leaving the relevant tables at `reltuples = -1`. That planner
mis-estimation expanded the RLS plan for 33 seconds.

The dashboard PostgreSQL 18 fixture now analyzes only the tables used by the
snapshot path after seeding. The same parameterized Prisma transaction then
completed `dashboard_snapshot_data` in 182 ms. No policy, index, grant, owner,
function signature, or application query changed.
