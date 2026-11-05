# D15 ledger readback: authenticated local entry point

The root-scoped D15 ledger runtime must be loaded from a private copy of an authenticated protected-main Git tree. Do not run `production-d15-ledger-runtime.mjs` or the repository checkout's `production-d15-ledger-readback.mjs` directly. Obtain this command from the GitHub protected-main page, not from a writable local checkout.

The operator uses the existing root profile `default`. Set `repo` to the canonical local repository path. For `authorize` and `run`, the tooling SHA must equal current protected main. For `recover` and `verify`, an older tooling SHA is accepted only if it is an ancestor of current protected main and matches the signed authorization.

```bash
set -euo pipefail
repo='/Users/abhiramteja/Downloads/genuine-scan-main'
operator_home="$HOME"
main_json="$(/usr/bin/env -i HOME=/nonexistent PATH=/usr/bin:/bin /usr/bin/curl --disable --fail --silent --show-error --noproxy '*' --proto '=https' --tlsv1.2 --max-time 20 'https://api.github.com/repos/T-ej2003/genuine-scan-main/branches/main')"
main_sha="$(printf '%s' "$main_json" | /usr/bin/env -i HOME=/nonexistent PATH=/usr/bin:/bin /usr/local/bin/node -e 'let s="";process.stdin.setEncoding("utf8");process.stdin.on("data",x=>{s+=x;if(s.length>1048576)process.exit(1)});process.stdin.on("end",()=>{try{const b=JSON.parse(s),h=b.commit?.sha;if(b.name!=="main"||b._links?.self!=="https://api.github.com/repos/T-ej2003/genuine-scan-main/branches/main"||!/^[a-f0-9]{40}$/.test(h)||b.commit.url!==`https://api.github.com/repos/T-ej2003/genuine-scan-main/commits/${h}`)process.exit(1);process.stdout.write(h)}catch{process.exit(1)}})')"
tooling_sha="$main_sha"
loader="$(/usr/bin/mktemp -d /tmp/mscqr-d15-loader.XXXXXXXX)"
cleanup() { /bin/rm -rf "$loader"; }
trap cleanup EXIT
/usr/bin/env -i HOME=/nonexistent PATH=/usr/bin:/bin GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 /usr/bin/git -C "$repo" -c core.fsmonitor=false merge-base --is-ancestor "$tooling_sha" "$main_sha"
/usr/bin/env -i HOME=/nonexistent PATH=/usr/bin:/bin GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 /usr/bin/git -C "$repo" -c core.fsmonitor=false show "$tooling_sha:scripts/aws/production-d15-ledger-readback.mjs" > "$loader/bootstrap.mjs"
/usr/bin/env -i HOME="$operator_home" PATH=/usr/bin:/bin AWS_PROFILE=default AWS_REGION=eu-west-2 AWS_DEFAULT_REGION=eu-west-2 /usr/local/bin/node "$loader/bootstrap.mjs" "$tooling_sha" "$repo" authorize /absolute/path/to/authorization.json
```

For `run`, use the same freshly authenticated loader sequence and replace the last three arguments with `run /absolute/path/to/authorization.json /absolute/path/to/receipt.json`. For `recover` and `verify`, set `tooling_sha` to the signed authorization's tooling SHA before the `git show` step, then use that mode and both absolute file paths. The bootstrap independently rechecks GitHub protected main, Git ancestry, its own bytes, source tree types, and the private copy before importing the runtime. It rejects an unauthorized source or changed copy before any AWS operation.

The copy contains only `scripts/aws` and the fixed ECS task-definition reader dependency. The source repository's object store supplies immutable Git objects to the private copy; Git replacement objects, inherited Git configuration, and filesystem monitor hooks are disabled. The copied runtime retains its KMS authorization, root identity, fixed task, audit, and receipt checks. A failed bootstrap performs no root-scoped operation. Preserve the authorization, intent, task and receipt files for audit and read-only recovery.
