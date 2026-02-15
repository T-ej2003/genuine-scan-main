export type HelpDocSlug =
  | "getting-access"
  | "setting-password"
  | "super-admin"
  | "licensee-admin"
  | "manufacturer"
  | "customer";

export type ScreenshotSpec = {
  file: string;
  capture: string;
  alt: string;
  note?: string;
};

export type HelpStep = {
  title: string;
  summary: string;
  bullets: string[];
  screenshots: ScreenshotSpec[];
};

export type HelpFaq = {
  question: string;
  answer: string;
};

export type HelpDoc = {
  slug: HelpDocSlug;
  title: string;
  summary: string;
  roleHeading?: string;
  isIntro?: boolean;
  canDo: string[];
  cannotDo?: string[];
  steps: HelpStep[];
  troubleshooting: HelpFaq[];
  faqs: HelpFaq[];
  recommendedImprovements?: string[];
};

const docs: Record<HelpDocSlug, HelpDoc> = {
  "getting-access": {
    slug: "getting-access",
    title: "Getting Access",
    summary:
      "How each user type gets access today, plus what is still manual in the current system.",
    isIntro: true,
    canDo: [
      "See the exact access path for Super Admin, Licensee/Admin, Manufacturer, and Customer.",
      "Understand who creates each account and where login starts.",
    ],
    steps: [
      {
        title: "Super Admin access",
        summary: "Super Admin users are platform-level users.",
        bullets: [
          "Current behavior: Super Admin accounts are created during setup or by an existing Super Admin.",
          "There is no end-user self-signup screen for Super Admin.",
          "After account creation, sign in from `/login`.",
        ],
        screenshots: [
          {
            file: "access-super-admin-login.png",
            capture: "Login page with Super Admin credentials entered.",
            alt: "Super Admin login screen",
          },
        ],
      },
      {
        title: "Licensee/Admin (brand/company) access",
        summary: "Licensee/Admin users are created by Super Admin.",
        bullets: [
          "Current behavior: Super Admin creates the licensee and admin user in the dashboard.",
          "Licensee/Admin receives credentials out-of-band (no invite email workflow in-app).",
          "User signs in at `/login`.",
        ],
        screenshots: [
          {
            file: "access-licensee-admin-created-user.png",
            capture: "Licensee creation form with admin details filled.",
            alt: "Licensee admin creation flow",
          },
        ],
      },
      {
        title: "Manufacturer (factory user) access",
        summary: "Manufacturer users are created by Super Admin or Licensee/Admin.",
        bullets: [
          "Current behavior: manufacturer accounts are created from `Manufacturers` page.",
          "There is no invite acceptance link today.",
          "Manufacturer signs in at `/login` with credentials provided by admin.",
        ],
        screenshots: [
          {
            file: "access-manufacturer-create-form.png",
            capture: "Manufacturers page with Add Manufacturer form open.",
            alt: "Manufacturer account creation",
          },
        ],
      },
      {
        title: "Customer (scanner / verification page) access",
        summary: "Customers can verify without admin-created accounts.",
        bullets: [
          "Current behavior: customer can scan as guest from `/verify/<code>` or `/scan?t=...`.",
          "Optional sign-in is available on verify page via Google or Email OTP.",
          "Customer does not need dashboard access.",
        ],
        screenshots: [
          {
            file: "access-customer-verify-entry.png",
            capture: "Public verify page with code result and sign-in options visible.",
            alt: "Customer verify page entry",
          },
        ],
      },
    ],
    troubleshooting: [
      {
        question: "I created a user but they cannot sign in.",
        answer:
          "Confirm email spelling, user role, and that the account is active. Then verify the password shared with the user is correct.",
      },
      {
        question: "Customer says sign-in is not visible on verify page.",
        answer:
          "Email OTP is always available. Google sign-in appears only when `VITE_GOOGLE_CLIENT_ID` is configured.",
      },
    ],
    faqs: [
      {
        question: "Is there an invite email flow today?",
        answer:
          "Not yet. Admin-created accounts are shared manually right now.",
      },
      {
        question: "Can customers self-register as dashboard users?",
        answer:
          "No. Customer identity is for verify-page ownership and fraud protection only.",
      },
    ],
    recommendedImprovements: [
      "Add invite links with expiry for Licensee/Admin and Manufacturer accounts.",
      "Add first-login invite acceptance page with forced password setup.",
    ],
  },
  "setting-password": {
    slug: "setting-password",
    title: "Setting Your Password",
    summary:
      "Role-specific password behavior for first login, password change, and password reset.",
    isIntro: true,
    canDo: [
      "Understand how password setup currently works for each role.",
      "Find the right path for password updates and recovery.",
    ],
    steps: [
      {
        title: "Super Admin password flow",
        summary: "Platform admin password is set at account creation.",
        bullets: [
          "Current behavior: password is assigned when account is created.",
          "After login, change password at `Account > Security`.",
          "Forgot-password self-service is not available in current UI.",
        ],
        screenshots: [
          {
            file: "password-superadmin-account-security.png",
            capture: "Account Settings page open on Security section.",
            alt: "Super Admin account security settings",
          },
        ],
      },
      {
        title: "Licensee/Admin password flow",
        summary: "Licensee/Admin password is set by admin during user creation.",
        bullets: [
          "Current behavior: no first-time set-password link.",
          "User signs in with provided password, then can change it in `Account > Security`.",
          "If password is forgotten, Super Admin must reset it manually.",
        ],
        screenshots: [
          {
            file: "password-licensee-change-password.png",
            capture: "Licensee/Admin account security form with current/new password fields.",
            alt: "Licensee admin change password form",
          },
        ],
      },
      {
        title: "Manufacturer password flow",
        summary: "Manufacturer password flow matches Licensee/Admin flow.",
        bullets: [
          "Current behavior: password is assigned by admin at creation.",
          "Manufacturer can update password in `Account > Security` after login.",
          "Forgot password requires admin reset (no reset email flow yet).",
        ],
        screenshots: [
          {
            file: "password-manufacturer-account-security.png",
            capture: "Manufacturer account settings security section.",
            alt: "Manufacturer password settings",
          },
        ],
      },
      {
        title: "Customer sign-in (no password)",
        summary: "Customer verify flow does not use persistent passwords.",
        bullets: [
          "Customer may sign in with Google on verify page.",
          "Customer may use Email OTP as guest fallback.",
          "No password reset is needed because OTP/Google is used instead.",
        ],
        screenshots: [
          {
            file: "password-customer-otp-request.png",
            capture: "Verify page email OTP request form.",
            alt: "Customer OTP request",
          },
          {
            file: "password-customer-otp-verify.png",
            capture: "Verify page with OTP input visible.",
            alt: "Customer OTP verify",
          },
        ],
      },
    ],
    troubleshooting: [
      {
        question: "User says old password works but change password fails.",
        answer:
          "Check that current password is entered correctly and new password confirmation matches.",
      },
      {
        question: "Forgot password link is missing.",
        answer:
          "That is current behavior. Password resets are admin-assisted today.",
      },
    ],
    faqs: [
      {
        question: "Do customers have dashboard passwords?",
        answer: "No. Customers use Google sign-in or email OTP on verify page.",
      },
      {
        question: "Can admins reset their own forgotten password?",
        answer: "Not from the current UI. Another admin must update it.",
      },
    ],
    recommendedImprovements: [
      "Add forgot-password email for Super Admin, Licensee/Admin, and Manufacturer users.",
      "Add forced password rotation policy for privileged roles.",
    ],
  },
  "super-admin": {
    slug: "super-admin",
    roleHeading: "Super Admin",
    title: "Super Admin",
    summary:
      "Platform-wide operations: licensees, allocation, oversight, policy, and incident response.",
    canDo: [
      "Create and manage licensees.",
      "Create Licensee/Admin and Manufacturer users.",
      "Allocate QR ranges and generate QR pools.",
      "Approve or reject QR requests.",
      "Monitor incidents, policy alerts, and audit evidence.",
    ],
    cannotDo: [
      "Cannot bypass signed-scan integrity checks.",
      "Cannot recover deleted physical labels once printed externally.",
    ],
    steps: [
      {
        title: "Create a licensee with admin access",
        summary: "Start by onboarding a brand/company tenant.",
        bullets: [
          "Open `Licensees` from sidebar.",
          "Click create/add and fill company + prefix details.",
          "Add initial admin details and save.",
        ],
        screenshots: [
          {
            file: "superadmin-create-licensee-form.png",
            capture: "Licensees page with create form filled and validation visible.",
            alt: "Create licensee form",
          },
        ],
      },
      {
        title: "Allocate QR inventory",
        summary: "Allocate range/quantity to maintain tenant supply.",
        bullets: [
          "Open `QR Requests` for pending asks, or use direct allocation tools.",
          "Approve request or allocate range manually.",
          "Verify allocation event appears in audit trail.",
        ],
        screenshots: [
          {
            file: "superadmin-approve-qr-request.png",
            capture: "QR Requests page with one pending item and Approve action visible.",
            alt: "Approve QR request",
          },
          {
            file: "superadmin-allocate-qr-range.png",
            capture: "Direct QR range allocation modal/page with values set.",
            alt: "QR range allocation",
          },
        ],
      },
      {
        title: "Investigate suspicious scans",
        summary: "Use incidents and policy pages for operational response.",
        bullets: [
          "Open `Incidents` and filter by status/severity.",
          "Review evidence and notes.",
          "Use `Policy Alerts` and `QR Tracking` for related scan anomalies.",
        ],
        screenshots: [
          {
            file: "superadmin-incident-list.png",
            capture: "Incidents page filtered to NEW/HIGH items.",
            alt: "Incident list view",
          },
          {
            file: "superadmin-policy-alerts.png",
            capture: "Policy alerts screen showing open alerts.",
            alt: "Policy alerts dashboard",
          },
        ],
      },
    ],
    troubleshooting: [
      {
        question: "Approve request fails with server error.",
        answer:
          "Check database connectivity and whether requested quantity exceeds available unallocated pool.",
      },
      {
        question: "Incident email alerts are not sent.",
        answer:
          "Verify SMTP env vars and active Super Admin email records.",
      },
    ],
    faqs: [
      {
        question: "Can Super Admin view all tenant data?",
        answer: "Yes, Super Admin is cross-tenant by design.",
      },
      {
        question: "Can Super Admin assign manufacturer batches directly?",
        answer:
          "The platform supports admin-driven allocations; normal workflow still routes operational ownership to Licensee/Admin.",
      },
    ],
  },
  "licensee-admin": {
    slug: "licensee-admin",
    roleHeading: "Licensee/Admin (brand/company)",
    title: "Licensee/Admin (brand/company)",
    summary:
      "Tenant operations: manufacturer management, QR requests, batch assignment, and routine monitoring.",
    canDo: [
      "Create and manage Manufacturer users under own licensee.",
      "Request additional QR inventory by quantity.",
      "Assign batches to manufacturers.",
      "View incidents and audit logs in own tenant.",
    ],
    cannotDo: [
      "Cannot access other licensees.",
      "Cannot perform Super Admin-only global allocation tasks.",
    ],
    steps: [
      {
        title: "Create a manufacturer account",
        summary: "Onboard a factory user before assignment.",
        bullets: [
          "Go to `Manufacturers`.",
          "Click add/create and fill required fields.",
          "Share credentials securely with the factory user.",
        ],
        screenshots: [
          {
            file: "licensee-create-manufacturer.png",
            capture: "Manufacturers page with Add Manufacturer form open.",
            alt: "Create manufacturer",
          },
        ],
      },
      {
        title: "Request more QR inventory",
        summary: "Submit quantity request to Super Admin.",
        bullets: [
          "Open `QR Requests`.",
          "Enter required quantity and optional note.",
          "Track status until approved.",
        ],
        screenshots: [
          {
            file: "licensee-qr-request-submit.png",
            capture: "QR request form with quantity and note fields filled.",
            alt: "Submit QR request",
          },
        ],
      },
      {
        title: "Assign received batch to manufacturer",
        summary: "Allocate quantity to production user.",
        bullets: [
          "Open `Batches`.",
          "Select a received/unassigned batch.",
          "Assign manufacturer and quantity.",
          "Confirm allocation in batch status.",
        ],
        screenshots: [
          {
            file: "licensee-assign-batch-manufacturer.png",
            capture: "Batch assignment modal showing manufacturer + quantity.",
            alt: "Assign batch to manufacturer",
          },
        ],
      },
      {
        title: "Review incidents and scan risk",
        summary: "Close loop on duplicate-risk events.",
        bullets: [
          "Open `Incidents` for customer fraud reports.",
          "Use `QR Tracking` to inspect scan timeline.",
          "Escalate critical findings to Super Admin.",
        ],
        screenshots: [
          {
            file: "licensee-incidents-overview.png",
            capture: "Incidents list scoped to licensee tenant.",
            alt: "Licensee incidents overview",
          },
          {
            file: "licensee-qr-tracking-filtered.png",
            capture: "QR Tracking page filtered by code or first-scan status.",
            alt: "QR tracking filtered view",
          },
        ],
      },
    ],
    troubleshooting: [
      {
        question: "Cannot see manufacturer in assignment dropdown.",
        answer:
          "Confirm manufacturer account is active and belongs to the same licensee.",
      },
      {
        question: "Batch quantity appears lower than expected.",
        answer:
          "Another assignment or print job may have reserved codes. Refresh and re-check available quantity.",
      },
    ],
    faqs: [
      {
        question: "Can Licensee/Admin export raw all-code inventory?",
        answer:
          "Raw QR code export is restricted to Super Admin in current access controls.",
      },
      {
        question: "Where do customer duplicate reports appear?",
        answer: "In the `Incidents` section for your tenant scope.",
      },
    ],
  },
  manufacturer: {
    slug: "manufacturer",
    roleHeading: "Manufacturer (factory user)",
    title: "Manufacturer (factory user)",
    summary:
      "Production execution: assigned batches, print jobs, and secure print pack handling.",
    canDo: [
      "View assigned batches only.",
      "Create print jobs for approved quantities.",
      "Download print packs and complete print confirmation flow.",
      "Monitor assigned batch scan activity in allowed scope.",
    ],
    cannotDo: [
      "Cannot request QR inventory.",
      "Cannot access other manufacturers or tenant admin settings.",
    ],
    steps: [
      {
        title: "Open assigned batches",
        summary: "Start each print run from assigned queue.",
        bullets: [
          "Sign in and open `Batches`.",
          "Review assigned quantities and status.",
          "Select the target batch.",
        ],
        screenshots: [
          {
            file: "manufacturer-batches-list.png",
            capture: "Manufacturer view of batches list with assigned items.",
            alt: "Manufacturer batch list",
          },
        ],
      },
      {
        title: "Create print job",
        summary: "Reserve exact quantity for production run.",
        bullets: [
          "Click create print job on batch.",
          "Enter quantity within available range.",
          "Submit and wait for job token generation.",
        ],
        screenshots: [
          {
            file: "manufacturer-create-print-job.png",
            capture: "Create print job modal with quantity set.",
            alt: "Create print job modal",
          },
        ],
      },
      {
        title: "Download print pack and print",
        summary: "Secure pack should be downloaded once and stored safely.",
        bullets: [
          "Download ZIP pack for the print job.",
          "Print labels according to factory SOP.",
          "Confirm status updates to printed/confirmed.",
        ],
        screenshots: [
          {
            file: "manufacturer-download-print-pack.png",
            capture: "Print job row showing download action.",
            alt: "Download print pack",
          },
          {
            file: "manufacturer-print-confirmed-status.png",
            capture: "Batch or print job status after successful confirmation.",
            alt: "Print confirmed status",
          },
        ],
      },
    ],
    troubleshooting: [
      {
        question: "Download blocked or token invalid.",
        answer:
          "Token may be expired or already used. Ask Licensee/Admin to issue a new authorized job if needed.",
      },
      {
        question: "Print job creation fails with quantity error.",
        answer:
          "Requested quantity exceeds remaining available unprinted codes. Lower quantity and retry.",
      },
    ],
    faqs: [
      {
        question: "Can I re-download the same pack many times?",
        answer: "No. The flow is intentionally restricted to reduce label leakage risk.",
      },
      {
        question: "Can I view incidents?",
        answer:
          "Incident management is for admin roles. Manufacturer users should escalate issues to Licensee/Admin.",
      },
    ],
  },
  customer: {
    slug: "customer",
    roleHeading: "Customer (scanner / verification page)",
    title: "Customer (scanner / verification page)",
    summary:
      "Public verification flow: scan status, ownership claim, and fraud reporting.",
    canDo: [
      "Scan and verify product authenticity.",
      "See clear result state: first scan, verified again, or possible duplicate.",
      "Sign in optionally with Google or email OTP.",
      "Claim product ownership after sign-in.",
      "Report suspected counterfeit with attached proof.",
    ],
    cannotDo: [
      "Cannot access admin dashboard features.",
      "Cannot view exact location traces for other scans.",
    ],
    steps: [
      {
        title: "Scan and read result state",
        summary: "Use verify URL from QR label.",
        bullets: [
          "Open the QR link or paste code in verify page.",
          "Wait for result card.",
          "Check status: `Verified Authentic`, `Verified Again`, or `Possible Duplicate`.",
        ],
        screenshots: [
          {
            file: "customer-verify-first-scan.png",
            capture: "Verify page showing first-time authentic result.",
            alt: "Customer first scan result",
          },
          {
            file: "customer-verify-again-scan.png",
            capture: "Verify page showing legit repeat (`Verified Again`).",
            alt: "Customer verified again result",
          },
          {
            file: "customer-possible-duplicate.png",
            capture: "Verify page showing possible duplicate warning and reasons.",
            alt: "Customer duplicate warning",
          },
        ],
      },
      {
        title: "Optional sign-in and ownership claim",
        summary: "Strengthens duplicate protection for your item.",
        bullets: [
          "Use Google sign-in or email OTP on verify page.",
          "After sign-in, click `Claim this product`.",
          "Claimed products show ownership status for your account.",
        ],
        screenshots: [
          {
            file: "customer-signin-otp.png",
            capture: "Verify page with Email OTP fields visible.",
            alt: "Customer OTP sign-in",
          },
          {
            file: "customer-claim-product.png",
            capture: "Verify page ownership panel with claim button or claimed badge.",
            alt: "Customer claim ownership",
          },
        ],
      },
      {
        title: "Report suspected counterfeit",
        summary: "Send a structured report when scan risk looks wrong.",
        bullets: [
          "Click `Report suspected counterfeit`.",
          "Fill what happened and add optional photos/proof.",
          "Submit and keep the report reference ID.",
        ],
        screenshots: [
          {
            file: "customer-report-counterfeit-form.png",
            capture: "Fraud report dialog with fields completed and screenshot placeholders.",
            alt: "Customer fraud report form",
          },
        ],
      },
    ],
    troubleshooting: [
      {
        question: "I scanned twice and got a warning.",
        answer:
          "If you are on a different device/account/location pattern, the system may classify it as possible duplicate. Sign in and claim ownership, then retry.",
      },
      {
        question: "I cannot receive OTP email.",
        answer:
          "Check spam folder, then retry after a minute. If still failing, contact support listed on verify page.",
      },
    ],
    faqs: [
      {
        question: "Do I need an account to verify?",
        answer: "No. Verification works for guests. Sign-in is optional but recommended for ownership protection.",
      },
      {
        question: "What data is stored from scans?",
        answer:
          "Scan events are stored for duplicate detection with coarse location signals and hashed IP fields.",
      },
    ],
  },
};

export const HELP_INTRO_SLUGS: HelpDocSlug[] = ["getting-access", "setting-password"];

export const HELP_ROLE_SLUGS: HelpDocSlug[] = [
  "super-admin",
  "licensee-admin",
  "manufacturer",
  "customer",
];

export const HELP_DOCS: HelpDoc[] = [
  ...HELP_INTRO_SLUGS.map((slug) => docs[slug]),
  ...HELP_ROLE_SLUGS.map((slug) => docs[slug]),
];

export const getHelpDoc = (slug?: string) => {
  if (!slug) return null;
  const normalized = String(slug).trim().toLowerCase() as HelpDocSlug;
  return docs[normalized] || null;
};

export const getHelpSlugForAppRole = (role?: string): HelpDocSlug | null => {
  if (!role) return null;
  const normalized = String(role).trim().toLowerCase();
  if (normalized === "super_admin") return "super-admin";
  if (normalized === "licensee_admin") return "licensee-admin";
  if (normalized === "manufacturer") return "manufacturer";
  return null;
};

export type ScreenshotRequirement = {
  file: string;
  pages: string[];
  capture: string;
};

export const getScreenshotRequirements = (): ScreenshotRequirement[] => {
  const byFile = new Map<string, ScreenshotRequirement>();

  for (const doc of HELP_DOCS) {
    for (const step of doc.steps) {
      for (const screenshot of step.screenshots) {
        const existing = byFile.get(screenshot.file);
        const pageLabel = doc.title;
        if (existing) {
          if (!existing.pages.includes(pageLabel)) existing.pages.push(pageLabel);
        } else {
          byFile.set(screenshot.file, {
            file: screenshot.file,
            pages: [pageLabel],
            capture: screenshot.capture,
          });
        }
      }
    }
  }

  return Array.from(byFile.values()).sort((a, b) => a.file.localeCompare(b.file));
};
