# MSCQR P0 Frontend Route Access Matrix

## Scope

This matrix records the P0 frontend route-access contract discovered from `src/App.tsx`, `src/app/route-metadata.ts`, `src/contexts/AuthContext.tsx`, and `src/features/layout/DashboardLayoutShell.tsx`.

Roles:

- `super_admin`
- `licensee_admin`
- `manufacturer`
- Anonymous/public visitor

Session behavior:

- Anonymous protected route: redirect to `/login`.
- Wrong-role protected route: redirect to `/dashboard`.
- Expired/invalid platform session: `GET /api/auth/me` failure clears auth and redirects to `/login`.
- Public routes under the auth-bootstrap skip list should not require `/api/auth/me`.

## Public Routes

| Route/path | Page/feature area | Public/protected | Allowed roles | Denied roles | Anonymous behavior | Wrong-role behavior | Expired/invalid session behavior | Sidebar/menu access | Direct URL access | Automated coverage |
|---|---|---|---|---|---|---|---|---|---|---|
| `/` | Home/landing | Public | All | None | Loads without auth bootstrap | N/A | N/A | No platform sidebar | Yes | P0 cleanliness, public access |
| `/trust` | Trust center | Public | All | None | Loads without auth bootstrap | N/A | N/A | No platform sidebar | Yes | P0 cleanliness, public access |
| `/privacy` | Privacy policy | Public | All | None | Loads without auth bootstrap | N/A | N/A | No platform sidebar | Yes | Pending P1 per-page |
| `/terms` | Terms of use | Public | All | None | Loads without auth bootstrap | N/A | N/A | No platform sidebar | Yes | Pending P1 per-page |
| `/cookies` | Cookie notice | Public | All | None | Loads without auth bootstrap | N/A | N/A | No platform sidebar | Yes | Pending P1 per-page |
| `/platform` | Marketing platform page | Public | All | None | Loads without auth bootstrap | N/A | N/A | No platform sidebar | Yes | P0 cleanliness, public access |
| `/solutions/brands` | Brand marketing | Public | All | None | Loads without auth bootstrap | N/A | N/A | No platform sidebar | Yes | P0 public access |
| `/solutions/garment-manufacturers` | Manufacturer marketing | Public | All | None | Loads without auth bootstrap | N/A | N/A | No platform sidebar | Yes | Pending P1 per-page |
| `/solutions/manufacturers` | Legacy redirect | Public redirect | All | None | Redirects to `/solutions/garment-manufacturers` | N/A | N/A | No platform sidebar | Yes | Pending P1 redirect |
| `/solutions/apparel-authenticity` | Solution page | Public | All | None | Loads without auth bootstrap | N/A | N/A | No platform sidebar | Yes | Pending P1 per-page |
| `/how-scanning-works` | Public scan explanation | Public | All | None | Loads without auth bootstrap | N/A | N/A | No platform sidebar | Yes | Pending P1 per-page |
| `/solutions/licensees` | Legacy redirect | Public redirect | All | None | Redirects to `/solutions/brands` | N/A | N/A | No platform sidebar | Yes | Pending P1 redirect |
| `/industries`, `/industries/*` | Legacy industry redirects | Public redirect | All | None | Redirects to `/solutions/apparel-authenticity` | N/A | N/A | No platform sidebar | Yes | Pending P1 redirect |
| `/about` | Company/about | Public | All | None | Loads without auth bootstrap | N/A | N/A | No platform sidebar | Yes | Pending P1 per-page |
| `/contact` | Contact | Public | All | None | Loads without auth bootstrap | N/A | N/A | No platform sidebar | Yes | Pending P1 per-page |
| `/request-access` | Request access form | Public | All | None | Loads without auth bootstrap | N/A | N/A | No platform sidebar | Yes | Pending P1 form |
| `/blog` | Public blog | Public | All | None | Loads without auth bootstrap | N/A | N/A | No platform sidebar | Yes | Pending P1 per-page |
| `/connector-download` | Connector download | Public/auth-optional | All | None | Loads without auth bootstrap | N/A | N/A | No platform sidebar | Yes | Pending P1 connector |
| `/help` | Help hub | Public | All | None | Loads | N/A | N/A | No platform sidebar | Yes | Pending P1 help |
| `/help/auth-overview` | Help article | Public/auth-aware | All | None | Loads | Role may affect context | Expired session should fall back safely | No platform sidebar | Yes | Pending P1 help |
| `/help/getting-access` | Help article | Public/auth-aware | All | None | Loads | Role may affect context | Expired session should fall back safely | No platform sidebar | Yes | Pending P1 help |
| `/help/setting-password` | Help article | Public/auth-aware | All | None | Loads | Role may affect context | Expired session should fall back safely | No platform sidebar | Yes | Pending P1 help |
| `/help/roles-permissions` | Help article | Public/auth-aware | All | None | Loads | Role may affect context | Expired session should fall back safely | No platform sidebar | Yes | Pending P1 help |
| `/help/licensee-admin` | Licensee help | Public/auth-aware | Public + licensee_admin + super_admin | Manufacturer redirected to role help when authenticated | Loads for public | Authenticated wrong role redirected to own help home | Safe fallback | No platform sidebar | Yes | Pending P1 help |
| `/help/manufacturer` | Manufacturer help | Public/auth-aware | Public + manufacturer + super_admin | Licensee redirected to role help when authenticated | Loads for public | Authenticated wrong role redirected to own help home | Safe fallback | No platform sidebar | Yes | Pending P1 help |
| `/help/customer` | Customer help | Public | All | None | Loads | N/A | N/A | No platform sidebar | Yes | P0 public access |
| `/help/support` | Support help | Public | All | None | Loads | N/A | N/A | No platform sidebar | Yes | Pending P1 help |
| `/help/super-admin`, `/help/incident-response`, `/help/policy-alerts`, `/help/incident-actions`, `/help/communications`, `/help/governance`, `/help/incidents` | Admin-only help | Protected by `HelpRoleRoute` | `super_admin` | `licensee_admin`, `manufacturer`, anonymous where `allowPublic=false` | Anonymous redirected to `/help/customer` | Wrong role redirected to role help home | Safe fallback | No platform sidebar | Yes | Pending P1 help |
| `*` | Not found | Public error | All | None | Shows 404 page | N/A | N/A | No platform sidebar | Yes | Pending P1 404 |

## Public QR/Verification Routes

| Route/path | Page/feature area | Public/protected | Allowed roles | Denied roles | Anonymous behavior | Wrong-role behavior | Expired/invalid session behavior | Sidebar/menu access | Direct URL access | Automated coverage |
|---|---|---|---|---|---|---|---|---|---|---|
| `/verify` | Manual QR entry / camera upload | Public | All | None | Loads without auth bootstrap | N/A | Customer auth optional | No platform sidebar | Yes | P0 public access |
| `/verify/:code` | Public QR result | Public | All | None | Loads result or safe error | N/A | Customer auth optional; platform auth not required | No platform sidebar | Yes | P0 valid, invalid, blocked, not-ready, suspicious, network, mobile |
| `/scan` | Scan landing or signed-token entry | Public | All | None | Without `?t=`, shows scan landing | N/A | Customer auth optional | No platform sidebar | Yes | Pending P1 signed-token scan |

## Auth Routes

| Route/path | Page/feature area | Public/protected | Allowed roles | Denied roles | Anonymous behavior | Wrong-role behavior | Expired/invalid session behavior | Sidebar/menu access | Direct URL access | Automated coverage |
|---|---|---|---|---|---|---|---|---|---|---|
| `/login` | Login/MFA | Auth route | Anonymous | Authenticated users | Shows login | Authenticated user redirected to `/dashboard` | Expired/invalid session remains on login | No platform sidebar | Yes | P0 cleanliness |
| `/accept-invite` | Invite acceptance | Auth route | Anonymous | Authenticated users | Shows invite flow | Authenticated user redirected to `/dashboard` | Expired/invalid session remains safe | No platform sidebar | Yes | Pending P1 auth flow |
| `/verify-email` | Email verification | Public | All | None | Shows verify email result | N/A | Safe public route | No platform sidebar | Yes | Pending P1 auth flow |
| `/forgot-password` | Password recovery | Auth route | Anonymous | Authenticated users | Shows forgot password | Authenticated user redirected to `/dashboard` | Expired/invalid session remains safe | No platform sidebar | Yes | P0 cleanliness |
| `/reset-password` | Password reset | Auth route | Anonymous | Authenticated users | Shows reset password | Authenticated user redirected to `/dashboard` | Expired/invalid session remains safe | No platform sidebar | Yes | Pending P1 auth flow |

## Protected Platform Routes

| Route/path | Page/feature area | Public/protected | Allowed roles | Denied roles | Anonymous behavior | Wrong-role behavior | Expired/invalid session behavior | Sidebar/menu access | Direct URL access | Automated coverage |
|---|---|---|---|---|---|---|---|---|---|---|
| `/dashboard` | Overview dashboard | Protected | `super_admin`, `licensee_admin`, `manufacturer` | Anonymous | Redirect to `/login` | N/A | Redirect to `/login` | Visible to all roles as Overview | Yes | P0 route, nav, cleanliness |
| `/licensees` | Brand/licensee admin | Protected | `super_admin` | `licensee_admin`, `manufacturer`, anonymous | Redirect to `/login` | Redirect to `/dashboard` | Redirect to `/login` | Visible only to `super_admin` as Brands | Yes | P0 route, nav, cleanliness |
| `/qr-codes` | Legacy QR codes redirect | Protected redirect | All authenticated roles | Anonymous | Redirect to `/login` | Redirects to `/scan-activity` after auth | Redirect to `/login` | No direct nav; alias for Scans | Yes | Pending P1 redirect |
| `/batches` | Batch/lot management | Protected | `super_admin`, `licensee_admin`, `manufacturer` | Anonymous | Redirect to `/login` | N/A | Redirect to `/login` | Visible to all roles | Yes | P0 route, nav, cleanliness |
| `/printer-setup` | Manufacturer printing setup | Protected | `manufacturer` | `super_admin`, `licensee_admin`, anonymous | Redirect to `/login` | Redirect to `/dashboard` | Redirect to `/login` | Visible only to `manufacturer` as Printing | Yes | P0 route, nav, cleanliness |
| `/code-requests` | QR allocation requests | Protected | `super_admin`, `licensee_admin` | `manufacturer`, anonymous | Redirect to `/login` | Redirect to `/dashboard` | Redirect to `/login` | Visible to `super_admin`, `licensee_admin` | Yes | P0 route, nav, cleanliness |
| `/qr-requests` | Legacy QR requests redirect | Protected redirect | `super_admin`, `licensee_admin` | `manufacturer`, anonymous | Redirect to `/login` | Redirect to `/dashboard` | Redirect to `/login` | No direct nav; alias for QR Requests | Yes | Pending P1 redirect |
| `/product-batches` | Legacy batches redirect | Public redirect to protected path | All after redirect auth applies | Anonymous effectively denied at `/batches` | Redirects to `/batches`, then login if anonymous | Protected route handles role | Redirect to `/login` after `/batches` | No nav | Yes | Pending P1 redirect |
| `/scan-activity` | QR scan analytics/activity | Protected | `super_admin`, `licensee_admin`, `manufacturer` | Anonymous | Redirect to `/login` | N/A | Redirect to `/login` | Visible to all roles as Scans | Yes | P0 route, nav, cleanliness |
| `/qr-tracking` | Legacy scan activity redirect | Protected redirect | `super_admin`, `licensee_admin`, `manufacturer` | Anonymous | Redirect to `/login` | N/A | Redirect to `/login` | No direct nav; alias for Scans | Yes | Pending P1 redirect |
| `/manufacturers` | Manufacturer/team management | Protected | `super_admin`, `licensee_admin` | `manufacturer`, anonymous | Redirect to `/login` | Redirect to `/dashboard` | Redirect to `/login` | Visible to `super_admin`, `licensee_admin` | Yes | P0 route, nav |
| `/audit-history` | Audit/history | Protected | `super_admin`, `licensee_admin`, `manufacturer` | Anonymous | Redirect to `/login` | N/A | Redirect to `/login` | Visible to all roles as History | Yes | P0 route, nav, cleanliness |
| `/audit-logs` | Legacy audit redirect | Protected redirect | `super_admin`, `licensee_admin`, `manufacturer` | Anonymous | Redirect to `/login` | N/A | Redirect to `/login` | Alias for History | Yes | Pending P1 redirect |
| `/incident-response` | Platform IR/issues | Protected | `super_admin` | `licensee_admin`, `manufacturer`, anonymous | Redirect to `/login` | Redirect to `/dashboard` | Redirect to `/login` | Visible only to `super_admin` as Issues | Yes | P0 route, nav, cleanliness |
| `/ir`, `/incidents` | Legacy incident redirects | Protected redirect | `super_admin` | `licensee_admin`, `manufacturer`, anonymous | Redirect to `/login` | Redirect to `/dashboard` | Redirect to `/login` | Alias for Issues | Yes | Pending P1 redirect |
| `/support` | Platform support center | Protected | `super_admin` | `licensee_admin`, `manufacturer`, anonymous | Redirect to `/login` | Redirect to `/dashboard` | Redirect to `/login` | Visible only to `super_admin` | Yes | P0 route, nav, cleanliness |
| `/release-readiness` | Release/security readiness | Protected | `super_admin` | `licensee_admin`, `manufacturer`, anonymous | Redirect to `/login` | Redirect to `/dashboard` | Redirect to `/login` | Visible only to `super_admin` | Yes | P0 route, nav |
| `/governance` | Governance/compliance | Protected | `super_admin` | `licensee_admin`, `manufacturer`, anonymous | Redirect to `/login` | Redirect to `/dashboard` | Redirect to `/login` | No sidebar item, direct URL allowed for `super_admin` | Yes | P0 route, cleanliness |
| `/incident-response/incidents/:id`, `/ir/incidents/:id` | IR incident detail | Protected | `super_admin` | `licensee_admin`, `manufacturer`, anonymous | Redirect to `/login` | Redirect to `/dashboard` | Redirect to `/login` | No separate sidebar item | Yes | Pending P1 detail |
| `/settings` | Organization/user settings | Protected | `super_admin`, `licensee_admin`, `manufacturer` | Anonymous | Redirect to `/login` | N/A | Redirect to `/login` | Visible to all roles | Yes | P0 route, nav, cleanliness |
| `/account` | Account/MFA/session settings | Protected | `super_admin`, `licensee_admin`, `manufacturer` | Anonymous | Redirect to `/login` | N/A | Redirect to `/login` | No sidebar item, menu access via user menu | Yes | P0 route |

## Coverage Notes

- P0 Playwright files after this pass:
  - `e2e/p0-access-control.spec.ts`
  - `e2e/p0-qr-verification-states.spec.ts`
  - `e2e/p0-ui-cleanliness.spec.ts`
- P0 route checks prioritize direct URL protection, sidebar/menu visibility, anonymous redirects, invalid-session redirects, logout clearing, QR result states, and production-facing visible text cleanliness.
- P1 should add seeded/live backend E2E coverage for full auth flows, legacy redirects, help role redirects, signed scan token flows, and form mutation permissions.
