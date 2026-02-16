import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  AlignmentType,
  Document,
  HeadingLevel,
  ImageRun,
  Packer,
  Paragraph,
  TextRun,
} from "docx";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");
const docsDir = path.join(repoRoot, "docs");
const outDir = path.join(docsDir, "role-manuals");
const screenshotsDir = path.join(repoRoot, "public", "docs");
const now = new Date().toISOString().slice(0, 10);

const pngDimensions = (buffer) => {
  const signature = "89504e470d0a1a0a";
  if (buffer.length < 24 || buffer.slice(0, 8).toString("hex") !== signature) return null;
  return {
    width: buffer.readUInt32BE(16),
    height: buffer.readUInt32BE(20),
  };
};

const toImageRun = (filename) => {
  const fullPath = path.join(screenshotsDir, filename);
  if (!fs.existsSync(fullPath)) return null;
  const data = fs.readFileSync(fullPath);
  const dim = pngDimensions(data) || { width: 1366, height: 768 };
  const maxWidth = 620;
  const maxHeight = 360;
  const ratio = Math.min(maxWidth / dim.width, maxHeight / dim.height, 1);
  const width = Math.max(320, Math.round(dim.width * ratio));
  const height = Math.max(180, Math.round(dim.height * ratio));

  return new ImageRun({
    data,
    transformation: { width, height },
  });
};

const heading = (text, level = HeadingLevel.HEADING_2) =>
  new Paragraph({
    heading: level,
    spacing: { before: 220, after: 120 },
    children: [new TextRun({ text })],
  });

const paragraph = (text) =>
  new Paragraph({
    spacing: { after: 100 },
    children: [new TextRun({ text })],
  });

const bullet = (text) =>
  new Paragraph({
    bullet: { level: 0 },
    spacing: { after: 70 },
    children: [new TextRun({ text })],
  });

const numbered = (index, text) => paragraph(`${index}. ${text}`);

const screenshotBlock = (filename, caption) => {
  const imageRun = toImageRun(filename);
  if (!imageRun) {
    return [
      paragraph(`Screenshot not available: ${filename}`),
      paragraph(`Capture note: ${caption}`),
    ];
  }

  return [
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 120, after: 60 },
      children: [imageRun],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 140 },
      children: [new TextRun({ text: `${caption} (${filename})`, italics: true })],
    }),
  ];
};

const docHeader = (title, audience) => [
  new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { after: 140 },
    children: [new TextRun({ text: title })],
  }),
  paragraph(`Document Type: User Operating Procedure`),
  paragraph(`Audience: ${audience}`),
  paragraph(`Version: 1.0`),
  paragraph(`Last Updated: ${now}`),
  paragraph(""),
  heading("1. Purpose"),
];

const commonSecuritySection = [
  heading("Control Notes"),
  bullet("Use only organization-approved accounts and devices."),
  bullet("Do not share credentials or one-time links."),
  bullet("Record incidents and corrective actions in system logs."),
  bullet("If an operation fails, capture timestamp, role, and page before escalation."),
];

const manuals = [
  {
    outFile: "AUTHENTICQR_SUPER_ADMIN_MANUAL.docx",
    title: "AuthenticQR - Super Admin User Manual",
    audience: "Platform Super Admin",
    content: [
      ...docHeader("AuthenticQR - Super Admin User Manual", "Platform Super Admin"),
      paragraph(
        "This manual defines the operational procedure for platform-level administration, tenant onboarding, QR request approvals, and incident response."
      ),
      heading("2. Access and Account Setup"),
      bullet("Account provisioning: created by platform owner or existing platform super admin."),
      bullet("First sign-in: use assigned credentials at /login."),
      bullet("Password recovery: use Forgot Password if enabled for your account."),
      ...screenshotBlock("access-super-admin-login.png", "Sign in page"),

      heading("3. Core Procedures"),
      paragraph("Procedure A - Create a licensee organization"),
      numbered(1, "Open Licensees."),
      numbered(2, "Select Add Licensee."),
      numbered(3, "Enter licensee profile and admin details."),
      numbered(4, "Submit and verify tenant appears in the list."),
      ...screenshotBlock("superadmin-create-licensee.png", "Create licensee flow"),

      paragraph("Procedure B - Approve QR inventory requests"),
      numbered(1, "Open QR Requests."),
      numbered(2, "Filter by Pending."),
      numbered(3, "Review quantity and decision note."),
      numbered(4, "Approve or Reject."),
      ...screenshotBlock("superadmin-approve-qr-request.png", "QR request approval"),

      paragraph("Procedure C - Incident Response operations"),
      numbered(1, "Open IR Center."),
      numbered(2, "Review Alerts and Incidents."),
      numbered(3, "Assign owner, severity, and priority."),
      numbered(4, "Apply containment action only with reason."),
      numbered(5, "Track communications and closure notes."),
      ...screenshotBlock("ir-dashboard.png", "IR dashboard"),
      ...screenshotBlock("ir-policy-create.png", "Policy rule creation"),
      ...screenshotBlock("ir-incident-actions.png", "Containment actions"),
      ...screenshotBlock("ir-communication-compose.png", "Incident communications"),

      heading("4. Troubleshooting"),
      bullet("If approval controls are missing, verify role is Platform Super Admin."),
      bullet("If IR actions fail, check incident status and required reason fields."),
      bullet("If email send fails, verify SMTP and sender configuration."),
      ...commonSecuritySection,
    ],
  },
  {
    outFile: "AUTHENTICQR_LICENSEE_ADMIN_MANUAL.docx",
    title: "AuthenticQR - Licensee/Admin User Manual",
    audience: "Licensee/Admin (brand/company)",
    content: [
      ...docHeader("AuthenticQR - Licensee/Admin User Manual", "Licensee/Admin (brand/company)"),
      paragraph(
        "This manual defines organization-scoped procedures for QR inventory requests, manufacturer onboarding, and batch assignment."
      ),
      heading("2. Access and Password"),
      bullet("Account provisioning: invited by Super Admin or org admin."),
      bullet("Invite acceptance: use one-time link, set password, then sign in."),
      bullet("Reset path: Forgot Password from /login."),
      ...screenshotBlock("password-accept-invite.png", "Accept invite and set password"),
      ...screenshotBlock("password-forgot-password.png", "Forgot password request"),
      ...screenshotBlock("password-reset-password.png", "Reset password"),

      heading("3. Core Procedures"),
      paragraph("Procedure A - Request QR inventory"),
      numbered(1, "Open QR Requests."),
      numbered(2, "Enter quantity and optional note."),
      numbered(3, "Submit request."),
      numbered(4, "Track decision from Super Admin."),
      ...screenshotBlock("licensee-request-qr-inventory.png", "QR inventory request"),

      paragraph("Procedure B - Create manufacturer account"),
      numbered(1, "Open Manufacturers."),
      numbered(2, "Select Add Manufacturer."),
      numbered(3, "Enter contact and login details."),
      numbered(4, "Send invite."),
      ...screenshotBlock("licensee-create-manufacturer.png", "Manufacturer onboarding"),

      paragraph("Procedure C - Assign received batch"),
      numbered(1, "Open Batches."),
      numbered(2, "Open Actions for a received batch."),
      numbered(3, "Choose Assign Manufacturer."),
      numbered(4, "Set quantity and confirm."),
      ...screenshotBlock("licensee-assign-batch.png", "Batch assignment"),

      heading("4. Troubleshooting"),
      bullet("If quantity fails, reduce assignment to available balance."),
      bullet("If manufacturer cannot see a batch, confirm assignment and account status."),
      bullet("If request is not visible, refresh QR Requests and verify filter."),
      ...commonSecuritySection,
    ],
  },
  {
    outFile: "AUTHENTICQR_MANUFACTURER_MANUAL.docx",
    title: "AuthenticQR - Manufacturer User Manual",
    audience: "Manufacturer (factory user)",
    content: [
      ...docHeader("AuthenticQR - Manufacturer User Manual", "Manufacturer (factory user)"),
      paragraph(
        "This manual defines print workflow controls for assigned batches, secure ZIP download, and printed-status confirmation."
      ),
      heading("2. Access and Password"),
      bullet("Account provisioning: invited by licensee admin or super admin."),
      bullet("Use invite link for initial password setup."),
      bullet("Use Forgot Password when needed."),
      ...screenshotBlock("access-super-admin-login.png", "Sign in page"),

      heading("3. Print Workflow"),
      paragraph("Procedure A - Create print job"),
      numbered(1, "Open Batches."),
      numbered(2, "Select Create Print Job on assigned batch."),
      numbered(3, "Enter quantity to print."),
      numbered(4, "Generate print job."),
      ...screenshotBlock("manufacturer-create-print-job.png", "Create print job"),

      paragraph("Procedure B - Download secure print pack"),
      numbered(1, "After job creation, select Download ZIP."),
      numbered(2, "Store ZIP in controlled print environment."),
      numbered(3, "Print labels for approved quantity only."),
      ...screenshotBlock("manufacturer-download-print-pack.png", "Download secure print pack"),

      paragraph("Procedure C - Verify print status"),
      numbered(1, "Return to Batches list."),
      numbered(2, "Confirm printed status is updated."),
      ...screenshotBlock("manufacturer-print-status.png", "Print status confirmation"),

      heading("4. Troubleshooting"),
      bullet("If Create Print Job is unavailable, confirm batch is assigned to your account."),
      bullet("If download is blocked, generate a new print job for remaining quantity."),
      bullet("If status does not update, refresh and escalate with batch ID and time."),
      ...commonSecuritySection,
    ],
  },
  {
    outFile: "AUTHENTICQR_CUSTOMER_MANUAL.docx",
    title: "AuthenticQR - Customer Verification Manual",
    audience: "Customer (scanner / verification page)",
    content: [
      ...docHeader("AuthenticQR - Customer Verification Manual", "Customer (scanner / verification page)"),
      paragraph(
        "This manual explains the public verification process, result interpretation, and counterfeit reporting."
      ),
      heading("2. Access"),
      bullet("No account is required to verify a product."),
      bullet("Open /verify and scan or enter the QR code."),
      bullet("Optional sign-in methods may be available for ownership protection."),

      heading("3. Result Interpretation"),
      paragraph("Result A - Verified Authentic"),
      bullet("Meaning: first valid verification for this printed code."),
      ...screenshotBlock("customer-first-verification.png", "First-time verification"),

      paragraph("Result B - Verified Again"),
      bullet("Meaning: same customer/device repeating a valid check."),
      ...screenshotBlock("customer-verified-again.png", "Legitimate repeat verification"),

      paragraph("Result C - Possible Duplicate"),
      bullet("Meaning: unusual pattern detected (for example many scans in short time or cross-device pattern)."),
      bullet("Action: review reasons shown on page and report if suspicious."),
      ...screenshotBlock("customer-possible-duplicate.png", "Possible duplicate state"),

      heading("4. Report Suspected Counterfeit"),
      numbered(1, "Select Report suspected counterfeit."),
      numbered(2, "Choose issue type and provide notes."),
      numbered(3, "Attach optional image evidence."),
      numbered(4, "Submit report for investigation."),
      ...screenshotBlock("customer-report-dialog.png", "Counterfeit report form"),

      heading("5. Troubleshooting"),
      bullet("If verification is unavailable, retry after a short delay."),
      bullet("If code is not recognized, verify label integrity and contact support."),
      bullet("If possible duplicate appears, avoid purchase/use until confirmation."),
      ...commonSecuritySection,
    ],
  },
];

const writeManual = async (manual) => {
  const doc = new Document({
    sections: [{ children: manual.content }],
  });
  const outPath = path.join(outDir, manual.outFile);
  const buffer = await Packer.toBuffer(doc);
  fs.writeFileSync(outPath, buffer);
  return outPath;
};

async function main() {
  fs.mkdirSync(outDir, { recursive: true });
  const created = [];
  for (const manual of manuals) {
    // eslint-disable-next-line no-await-in-loop
    const outPath = await writeManual(manual);
    created.push(path.relative(repoRoot, outPath));
  }
  // eslint-disable-next-line no-console
  console.log(`Created role manuals:\n${created.map((p) => `- ${p}`).join("\n")}`);
}

main().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error);
  process.exit(1);
});
