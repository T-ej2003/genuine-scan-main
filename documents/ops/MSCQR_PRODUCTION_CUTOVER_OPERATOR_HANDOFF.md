# Production cutover operator credential handoff

Run the command emitted by `stage-b:prepare-cutover-runtime` from the protected-main checkout in a trusted interactive terminal. It must use the canonical launcher:

```sh
npm run stage-b:run-cutover-operator -- --config <private-runtime-config> --config-sha256 <runtime-config-sha256> --source-sha <full-protected-main-sha> --rotation-id <rotation-id>
```

The launcher requires standard input and output to be TTYs. It reads the exact verifier MFA device ARN (`arn:aws:iam::368992683803:mfa/mscqr-production-bootstrap-operator`), strict-onboarding administrator email/password, and tenant-canary email/password directly from `/dev/tty` with echo disabled. The serial is an IAM MFA device identifier, never a six-digit TOTP. Values are never command arguments, shell assignments, files, evidence, or launcher output. They exist only in launcher/child memory and are removed from the launcher environment immediately after the child starts or fails.

Use the existing authenticated local AWS and GitHub operator session; do not run `aws configure` or place credentials in shell startup files. The launcher passes only the runtime environment needed for the governed child plus the five prompted inputs. It does not pre-collect any MFA code. After the child validates the bootstrap verifier identity, it requests the verifier MFA code from the controlling TTY immediately before its STS `AssumeRole` call. Onboarding or tenant-canary MFA remains separate: if live onboarding returns `MFA_BOOTSTRAP`, the existing just-in-time controlling-TTY provider prompts at that point and immediately submits the code.

The child remains the sole mutation authority: `scripts/aws/run-production-cutover.mjs --mode production`. The launcher adds no AWS operation and does not replace its source, authorization, CAS, or mutation checks.
