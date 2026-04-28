# Legal / Compliance Document Requirements Brief

This brief is written from engineering evidence, not as legal advice. It is intended to help counsel or the founder draft the correct documents quickly and accurately.

## Implementation update

MSCQR now has public placeholder pages for:

- `/privacy`
- `/terms`
- `/cookies`

These pages are implementation-grounded and clearly marked as requiring lawyer review before public launch.

## Actual implementation facts that drive document needs

Based on repo evidence, MSCQR currently:

- authenticates operators with secure cookies and CSRF protections
- authenticates public/customer verification sessions with a dedicated verify-session cookie
- stores device/session continuity and workflow state in localStorage/sessionStorage/cookies
- supports support-ticket and incident workflows that can include screenshots, logs, and uploaded evidence
- stores or processes customer emails during verification flows
- stores manufacturing/printer workflow state on operator devices
- can enable Sentry telemetry on frontend and backend if DSNs are configured
- is hosted on AWS infrastructure with database and object storage integrations
- supports multiple business roles and likely processes personal data on behalf of licensees/manufacturers in at least some scenarios

## Mandatory vs recommended document set

| Document | Status | Why it is needed | What triggers the need | Where it should appear |
| --- | --- | --- | --- | --- |
| Privacy Policy / Privacy Notice | Mandatory | MSCQR processes personal data and device-related data | Auth cookies, verification sessions, support evidence, customer email, logs, AWS hosting | Public footer, login, verify flow, support flow |
| Terms of Service / Terms of Use | Mandatory | Commercial product launch needs contractual usage terms and liability framing | Paid/commercial SaaS operation, multi-role platform access | Public footer, onboarding flows, account creation/login |
| Cookie Notice / Cookie Policy | Mandatory in practice | MSCQR stores/accesses information on user devices | Cookies, localStorage, sessionStorage, device IDs, preference state | Public footer, privacy page, verification surfaces |
| Cookie Consent Banner | Conditional but likely needed if any non-essential storage/telemetry is enabled | UK/EU rules can require consent before non-essential storage/access | Optional telemetry, preference cookies, future analytics | Public shell before non-essential items are set |
| Data Processing Addendum | Mandatory for B2B deals where MSCQR acts as processor | Enterprise buyers will require Article 28-style terms | Licensee/manufacturer customer data processed by MSCQR as service provider | Contract pack / sales process / admin procurement |
| Acceptable Use Policy | Recommended, often bundled into terms | Clarifies misuse boundaries and abuse handling | Public verification, support system, admin/manufacturer misuse scenarios | Linked from Terms and support docs |
| Support / Contact Policy | Recommended but strongly advised | Sets response expectations and escalation paths | Support launcher, incident response, launch-day support | Footer, support screen, onboarding packet |
| Retention / Deletion Policy | Mandatory in practice | Needed to explain how long support, incident, and verification data is kept | Logging, screenshots, uploads, account and verification data | Privacy docs, support docs, DPA references |
| Internal incident response / breach handling document | Mandatory internally | Needed for actual breach handling and accountability | Support evidence, AWS hosted systems, customer data | Internal-only runbook set |
| Subprocessor / hosting disclosure | Recommended and often commercially expected | B2B buyers will ask where data is hosted and by whom | AWS hosting, optional observability providers, email or messaging vendors if used | Privacy page, DPA appendix, trust center |

## Document-by-document brief

## 1. Privacy Policy / Privacy Notice

### Must contain

- who MSCQR is and contact details for privacy queries
- what categories of data are collected for each role
- what device/session data is stored or accessed
- what data is collected during support and incident flows
- purposes of processing
- legal bases or equivalent lawful-processing explanations
- retention periods or retention criteria
- sharing with subprocessors or service providers
- international transfer language if relevant
- rights request process
- security summary in plain English
- children/minors statement if public use can involve consumers

### Implementation-specific topics to include

- `aq_access`, `aq_refresh`, `aq_csrf`
- `mscqr_verify_session`, `gs_device_claim`, `aq_vid`
- localStorage/sessionStorage continuity keys in verify/help/printer flows
- support screenshot and evidence uploads
- optional Sentry telemetry if enabled
- AWS hosting/object storage/database usage

## 2. Terms of Service / Terms of Use

### Must contain

- who may use MSCQR and under what authority
- acceptable use and prohibited activities
- verification-result limitations and disclaimers
- support availability disclaimers
- account responsibility and security obligations
- connector/software download terms for manufacturer-side tools
- IP ownership and licensing
- suspension/termination rights
- liability caps and governing law

### Implementation-specific topics to include

- public verification should not be positioned as legal proof beyond intended purpose
- manufacturer connector use should be subject to supported environment and installation conditions
- misuse of incident/support systems and QR generation flows should be prohibited

## 3. Cookie Notice / Cookie Policy

### Must contain

- inventory of cookies and similar technologies
- purpose of each category
- duration/expiry where known
- essential vs non-essential classification
- how users can manage settings
- relation to privacy policy

### Implementation-specific topics to include

- authentication cookies
- verification-session cookies
- anonymous/public device identifiers
- sidebar, help draft, printer onboarding, and calibration storage
- whether Sentry or any future analytics use storage or identifiers

## 4. Cookie Consent Banner

### Decision rule

- If only strictly necessary security/auth/core-service storage is used, disclosure may be enough.
- If non-essential diagnostics, preference storage, or telemetry are active, consent may be needed before they are set for UK/EU users.

### What to prepare if required

- accept / reject / manage options
- no deceptive design
- category-level controls
- default denial for non-essential items
- proof of consent choice storage and re-display path

## 5. Data Processing Addendum

### Must contain

- role allocation: controller vs processor
- subject matter and duration of processing
- categories of data and data subjects
- security obligations
- confidentiality obligations
- subprocessors and approval mechanism
- deletion/return obligations
- breach notification commitments
- audit/cooperation language

### Trigger in MSCQR

If licensees or manufacturers use MSCQR to process their customer or operator data, MSCQR likely acts as a processor for at least part of the service relationship.

## 6. Acceptable Use Policy

### Recommended content

- prohibited misuse of QR workflows
- no fraudulent brand claims
- no scraping or abuse of public verification
- no harmful uploads or malware
- no misuse of support/incident channels

## 7. Support / Contact Policy

### Recommended content

- support channels
- support hours and response targets
- severity classification
- what evidence may be collected
- emergency escalation path
- limits of support for local environments and printer hardware

## 8. Retention / Deletion Policy

### Must contain

- retention periods for auth, audit, verification, support, incident, and upload data
- deletion triggers
- customer offboarding process
- legal hold or fraud-investigation exception handling

### Why this is urgent

Repo evidence includes screenshots/logs/uploads and references to multi-day/month log retention expectations, but there is no formal policy surfaced.

## 9. Internal Incident Response / Breach Handling

### Should cover

- triage severity levels
- breach decision criteria
- regulatory/customer notification path
- forensic evidence preservation
- communications ownership
- restore/rollback decision points

MSCQR already has strong internal runbook material, but launch readiness requires named owners and rehearsal evidence.

## Lawyer review notes

### Engineering inference

- MSCQR likely needs all documents listed above except the consent banner, which depends on the final storage classification and deployed telemetry behavior.
- A DPA is likely needed for enterprise/B2B contracting.

### Legal certainty still required

- final controller/processor role allocation
- final cookie-consent requirement
- governing law and jurisdiction
- consumer protection obligations if public users interact directly
- exact retention schedules and breach notification wording

## Suggested placement in the app/site

- Public footer: Privacy, Terms, Cookies, Support, Trust
- Login page: Privacy and Terms links
- Verify flow: Privacy and Cookies links before data submission
- Support launcher: short privacy notice for screenshots/logs/uploads
- Connector download page: download terms, support scope, integrity guidance

## Lawyer-ready handoff summary

Please draft and review launch-ready legal documents for MSCQR based on the following confirmed implementation facts:

1. Operator login uses secure cookies and CSRF protections.
2. Public verification uses a dedicated verification session cookie plus browser storage/device continuity helpers.
3. The product may collect customer email and verification/session metadata.
4. Support and incident flows can collect screenshots, logs, and uploaded evidence.
5. The service is hosted on AWS and uses object storage/database services.
6. Frontend and backend Sentry telemetry may be enabled by configuration.
7. The service supports super admin, licensee admin, manufacturer, and public verification users.
8. A downloadable local print connector is distributed to some users, which should be covered in terms and support scope.

## Useful regulatory guidance

- [ICO: Cookies and similar technologies](https://ico.org.uk/for-organisations/direct-marketing-and-privacy-and-electronic-communications/guide-to-pecr/cookies-and-similar-technologies/)
- [ICO: What are storage and access technologies?](https://ico.org.uk/for-organisations/direct-marketing-and-privacy-and-electronic-communications/guidance-on-the-use-of-storage-and-access-technologies/what-are-storage-and-access-technologies/)
- [ICO: Privacy notices, transparency and control](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/transparency-and-the-right-to-be-informed/privacy-notices-transparency-and-control/)
- [ICO: Contracts and liabilities between controllers and processors](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/accountability-and-governance/contracts-and-liabilities-between-controllers-and-processors-multi/)

These sources inform the engineering brief. Counsel should still provide the final legal position.
