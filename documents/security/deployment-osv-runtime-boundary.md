# Deployment Audit runtime provenance safety stop

## Invalidated proof

The browser P1 against `c4b0a0b7030b8371537aa8c5a76d5cfeb79ab468` is valid.
The earlier module census did not prove absence from the executable artifact.
Its claim that braces was positively proven build-only is withdrawn.

The exact attack was reproduced before editing through four independent paths:

| Hook | Package-derived code executes | Package module identity present | Old gate passes |
|---|---|---|---|
| transform | true | false | true |
| virtual load | true | false | true |
| renderChunk | true | false | true |
| generateBundle mutation | true | false | true |

Fixtures read executable code from a vulnerable development package, emit a real
production library artifact, and execute that artifact in a Node VM. They do not
search for package names or advisory identifiers in output. Identifying banners
are absent. The module census omits the package despite executable contribution.

## Local fail-closed correction

Module presence may establish YES. Missing module identity establishes UNKNOWN,
not NO. The local gate no longer exempts any vulnerable package on that basis.
Browser evidence explicitly states `executableProvenance: INCOMPLETE`.
Unknown contributions fail closed. The four reproductions are permanent tests;
clean reports still pass. No advisory-specific exception, plugin/package allowlist,
severity reduction, or manifest-only exemption is introduced.

This is a safety correction, **not a merge-ready solution to the CI blocker**.
The actual current source scan still finds unpatched braces. The fresh production
build cannot independently establish NO executable contribution from that package,
so the corrected local gate rejects it as UNKNOWN. These local changes are not
pushed; the required pre-push gate is not green.

## Why native evidence is insufficient

Native module IDs and output chunks describe the bundler's graph, not every origin
of bytes supplied by arbitrary build hooks. A plugin can read package code and
append it to an already attributed chunk, or expose it under an unrelated virtual
ID. Hook-produced source maps are supplied by that same emitter: optional or
incomplete maps cannot be evidence of absence, and their source labels are not an
independent package-origin witness. A post-render/bundle mutation can occur after
graph collection. Observing that a hook changed code does not recover its package
origin. Conservatively treating unproved contribution as UNKNOWN is safe; claiming
complete provenance from those native fields is not.

Positive NO would require an independently enforced, complete code-origin chain
through build-tool execution, or removal of the vulnerable build dependency path.
The current repository supplies neither. A package/plugin-name allowlist or a
sourcemap-trust assumption would repeat the security error and is not recommended.
A complete arbitrary-JavaScript origin-tracking system is not a small CI patch.
No such new build/security architecture has been implemented.

## Emission boundary inventory

| Path | Evidence available | Local decision with relevant finding |
|---|---|---|
| Normal/transitive imports | Positive module identities | YES blocks; missing identity UNKNOWN blocks |
| Dynamic imports | Positive graph, unresolved expressions rejected | YES/UNKNOWN blocks |
| Lazy chunks | Positive graph/chunks | YES/UNKNOWN blocks |
| Browser worker builds | Separate worker graph | YES/UNKNOWN blocks |
| Transform/generated helpers | Emitter may supply untracked bytes | UNKNOWN blocks |
| Virtual loads | Virtual identity may hide source package | UNKNOWN blocks |
| renderChunk | Existing chunk may receive copied bytes | UNKNOWN blocks |
| generateBundle/emitted JS | Existing chunks may mutate; new assets may be untracked | UNKNOWN blocks |
| writeBundle/post-processing | Output can change after graph capture | UNKNOWN blocks |
| Minification/tree shaking | No complete independent origin witness | UNKNOWN blocks |
| Docker output copy to Nginx | Packaging contract establishes copied output, not byte origins | UNKNOWN blocks |

11 paths fail closed; zero paths grant an absence-based exemption. None has a
complete independent final-artifact provenance chain. This deliberately prevents
an unsafe green result rather than claiming the entire original matrix passed.

## Unchanged release and Stage B scope

The earlier Stage B closure failure was the newly added unclassified
`.security/osv-production.toml`. Its deletion already fixed the net protected-main
diff; local complete Stage B closure passed at c4b0a0b7. Manifest/lockfile changes
still require fresh frontend image publication. Historical-runtime authority,
broker binding, worker census/retention, printing, worker lifecycle, and AWS state
are untouched by this safety correction.

Recommendation: keep #618 unmerged. Review a separately scoped, compatible removal
of the unpatched build dependency path before considering a major framework
migration. Do not substitute a vulnerability waiver or incomplete provenance proof.


## Dependency-removal investigation: true stop boundary

Fresh registry and lockfile inspection confirms that Tailwind 3.4.19 is the newest
published stable 3.x release. All compatible parents are already current:
chokidar 3.6.0, fast-glob 3.3.3, micromatch 4.0.8, braces 3.0.3.
No compatible parent update removes the vulnerable dependency.

The following three suffixes occur beneath each root listed below:

| Suffix below tailwindcss@3.4.19 | Edge constraints | Used by current build | Safe removal/replacement |
|---|---|---|---|
| chokidar@3.6.0 → braces@3.0.3 | ^3.6.0 → ~3.0.2 | CLI watch dependency; installed by canonical Tailwind package | Not independently removable from supported package closure |
| micromatch@4.0.8 → braces@3.0.3 | ^4.0.8 → ^3.0.3 | Yes: content path matching | No compatible parent upgrade |
| fast-glob@3.3.3 → micromatch@4.0.8 → braces@3.0.3 | ^3.3.2 → ^4.0.8 → ^3.0.3 | Yes: source content scanning | No compatible parent upgrade |

| Root package | Route to Tailwind | Why present | Removal outcome |
|---|---|---|---|
| tailwindcss (^3.4.17) | direct 3.4.19 | Active PostCSS compiler in postcss.config.js | Removing it breaks current styling build |
| tailwindcss-animate (^1.0.7) | peer >=3.0.0 or insiders → 3.4.19 | Active Tailwind plugin; dialogs, sheets, menus, notifications use enter/exit/fade/zoom/slide utilities | Not unused; removal changes UI and leaves direct Tailwind path |
| @tailwindcss/typography (^0.5.16), locked 0.5.19 | peer >=3.0.0 or insiders or >=4 prerelease → 3.4.19 | Declared development peer; not listed in current Tailwind plugin config | Removing it cannot eliminate direct Tailwind path; left untouched |

These roots crossed with the three suffixes enumerate all nine dependency-tree
routes to the single deduplicated braces instance. Its direct parents are chokidar
and micromatch. The existing generated production CSS contains animate-in and
enter keyframes, confirming that the animation plugin is not merely declared.
The repository has no equivalent existing enter/exit plugin to substitute without
changing behavior. Replacing animate alone cannot remove Tailwind's own paths.

Registry endpoints checked: tailwindcss, chokidar, fast-glob, micromatch, braces at
https://registry.npmjs.org/. The published Tailwind 4 line changes the framework
and PostCSS integration; see https://tailwindcss.com/docs/upgrade-guide.
This is the explicitly prohibited major-migration boundary, not a lockfile-only
repair. No migration, dependency removal, override, vendoring, waiver, or downgrade
was attempted. Manifest and lockfile remain unchanged.

Recommendation: separately review a bounded Tailwind 4 build/styling migration
with dialog/sheet/menu animation and browser-compatibility acceptance checks, or
wait for a compatible upstream remediation. Keep the fail-closed corrections and
35 hostile regressions locally intact. Do not merge the currently green remote
head: its browser plugin-emission P1 remains applicable until the local correction
is committed, and that correction correctly blocks the unresolved braces finding.


## Authorized time-bounded CVE-specific acceptance (2026-10-03)

The owner authorized a narrowly scoped non-runtime risk acceptance after reviewing
actual CVE reachability, rather than authorizing a framework migration or generic
browser-provenance exception. This supersedes the migration recommendation above
for the current release only; the vulnerability and earlier P1 remain truthful.

Advisory: GHSA-vfj7-8cjw-p6xm / CVE-2026-93687. Package: braces 3.0.3.
Severity: HIGH, CVSS 8.7. No upstream patched release is currently available.
Recursive walkers in compile.js, expand.js and stringify.js can exhaust the stack
when processing deeply nested brace ASTs under the 10,000-character input limit.
An uncaught RangeError can terminate the JavaScript process. This is not code
execution; the attacker must control the pattern passed to the affected walker.

Installed callers are Tailwind → chokidar → braces, Tailwind → micromatch → braces,
and Tailwind → fast-glob → micromatch → braces. Instrumenting the actual production
build observed eight braces calls using exactly these repository-controlled globs:

- ./pages/**/*.{ts,tsx}
- ./components/**/*.{ts,tsx}
- ./app/**/*.{ts,tsx}
- ./src/**/*.{ts,tsx}

No application source imports these build dependencies. Backend/worker use their
separate dependency closure, whose lockfile contains no braces. The frontend server
runs Nginx. A fresh current Vite build inspected 1,606 mapped sources with no braces
library or recursive-walker implementation. Audited current build configuration
provides no code-injection path copying that implementation into browser output.
Production requests do not become Tailwind glob configuration or trigger runtime
Tailwind compilation. This supports the specific reviewed NO-runtime/NO-attacker-
input decision; it is not a universal native-module-provenance proof.

Owner: @T-ej2003, the repository CODEOWNERS owner. Created: 2026-10-03.
Expires: 2026-11-02, exclusive. Enforcement blocks on that date and thereafter.
Record: documents/security/osv-non-runtime-acceptance.json. It uses the same exact
scope/package/advisory/rationale/owner/expiresOn semantics as the dependency audit,
with additional version/CVE, reachability and input-snapshot bindings.

The protected-source acceptance is review authority, not unsigned runtime discovery.
Its reachability snapshot covers source, build scripts/configuration, packaging,
workflows and locked dependencies; changes require a new explicit review. A fresh
canonical build must have the same snapshot before and after compilation and again
at enforcement. Custom build/plugin options, positive browser module evidence,
backend/worker lockfile presence, non-dev instances, wrong/mixed scan scopes,
unknown reviewed execution/input status, fixed upstream advisory events, stale or
duplicate entries, missing reports, and expiry block. Module absence alone still
cannot exempt anything. Plugin-copy regressions remain permanently fail-closed.

OSV scans without exclusions and uploads raw findings. Enforcement prints the
unchanged advisory/severity, no-patch disposition, owner and expiry separately as
TIME_BOUNDED_NON_RUNTIME_ACCEPTANCE; it does not print zero vulnerabilities.
The evidence artifact includes the accepted finding and fresh build snapshot.

Security debt: prefer a compatible patched braces/Tailwind dependency path when
available. Otherwise review Tailwind 4 separately, including UI animations and
browser compatibility. This PR changes neither framework nor application behavior.


### Deployment-time expiry revalidation

Exact-head review of 642a853 found a delayed-release P2: a successful audit before
midnight could otherwise be replayed after expiry. The fix binds the deadline to
the immutable target commit's acceptance blob. Final required-gate sanity reads
that exact Git object after authenticating the successful target workflow runs.
The production runner repeats this check after environment approval and at every
subsequent shell-step boundary. No branch/environment deadline can override it.
A new step cannot begin after expiry, even when the prior audit conclusion was
success. Operations already in progress are not forcibly killed at midnight;
after expiry the next step blocks and needs reviewed remediation/renewal. This
changes only time-window enforcement, not release, worker or component authority.
The permanent regression simulates November 1 success followed by November 2
production dispatch and verifies zero mutation callbacks.


### ProviderReadOnly reconciler security-owner revalidation (2026-10-04)

The owner authorized fresh revalidation of the complete focused reconciler
candidate based on protected main 1df1d48015440ca13e6ebbe87a0192543438b039.
The unchanged broad boundary independently reproduces previous hash
`e39ae7f5a60a203c7a345a188de898121cb082851a34df0d94c4d8e902dcfe8f`
and candidate hash
`2071a78692c0379a3799984eed742cbac1b22a7899a59c019014a54d53de21df`.
Exactly two covered inputs changed: the ProviderReadOnly reconciliation contract
and its tests. Operations/security documentation lies outside this boundary.

A fresh instrumented production build observed four braces 3.0.3 calls with
exactly the four repository-controlled globs documented above. Neither changed
input loaded in the build. Inspection of 1,606 source-map sources found no braces
library/affected recursive-walker implementation. Backend/worker lockfile has no
braces instance; canonical packaging retains their separate pruned dependency
closure and the frontend's Nginx/static artifact runtime. Build configuration,
plugins, dependency locks and runtime packaging are unchanged.

The reconciler consumes policy/evidence/AWS data through JSON normalization,
canonical serialization, hashes, exact comparisons and explicit CLI arguments.
Its new logic only reverses enumerated policy statement additions. No reconciler
value becomes a Tailwind glob or reaches braces/micromatch/fast-glob evaluation.
HTTP, QR, database, queue, runtime environment and approval inputs do not become
content-discovery configuration or trigger runtime Tailwind compilation.
There is no new braces call site, input source or attacker-controlled pattern.

This revalidates the specific CVE reachability decision, not universal browser
plugin provenance. The finding remains HIGH and unpatched. Only the acceptance
input hash is rebound; owner, scope, rationale, advisory, version and exclusive
2026-11-02 expiry remain unchanged. Future source changes still invalidate it.


### FinalApplyWrite policy compaction revalidation (2026-10-06)

Exact-head review of PR #627 reproduced the prior protected-main fingerprint
`6afc66c6b2e0c38595e609223c7c1fa1e3ac54c3c59f51ef85ed1ece009252db` and the
candidate fingerprint
`7ce208d9b0bd5f0a2f8762fb370b4148d12e4fa371e2cefad3b5d415c618649e`.
Each of the three covered changes independently invalidates the broad snapshot:
the FinalApplyWrite policy builder, its governed convergence command, and its
focused test. Dependency locks, Tailwind configuration, Dockerfiles, application
source and runtime-image inputs are unchanged.

Raw OSV Scanner 2.6.0 reports the same single advisory before and after:
GHSA-vfj7-8cjw-p6xm / CVE-2026-93687 for dev-only braces 3.0.3. The dependency
paths remain Tailwind through chokidar and through micromatch/fast-glob. The
changed release scripts use Node standard-library and local IAM/release modules;
the test additionally uses js-yaml. None imports braces, Tailwind, chokidar,
micromatch or fast-glob, supplies content globs, or enters the browser bundle.

A fresh canonical production build again excludes braces from the browser
closure. Backend and worker retain a separate lockfile with no braces instance,
and the frontend runtime remains static Nginx output. The only vulnerable
execution remains trusted Tailwind compilation with the four repository-owned
content globs documented above; production requests cannot control those
patterns. PR #627 adds no call site, attacker-controlled pattern or runtime-image
input for the affected recursive walker.

The advisory remains visible and fail-closed for runtime or unknown reachability.
Only the existing acceptance input hash is rebound. Its advisory, package,
version, scope, rationale, owner and exclusive 2026-11-02 expiry are unchanged.
