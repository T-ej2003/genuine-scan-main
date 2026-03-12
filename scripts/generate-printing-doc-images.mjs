import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");
const outDir = path.join(repoRoot, "public", "docs");

const shell = (title, subtitle, content) => `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>${title}</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #eef2f7;
        --panel: #ffffff;
        --panel-soft: #f7fafc;
        --line: #d8e2ef;
        --text: #10253f;
        --muted: #5f7287;
        --nav: #0d2138;
        --accent: #10b981;
        --accent-soft: #ecfdf5;
        --warning: #f59e0b;
        --warning-soft: #fff7ed;
        --slate: #334155;
        --slate-soft: #e2e8f0;
      }

      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: "Inter", "Segoe UI", Arial, sans-serif;
        background: linear-gradient(180deg, #dbe7f5 0%, #eef2f7 100%);
        color: var(--text);
      }

      .frame {
        width: 1500px;
        height: 860px;
        margin: 0 auto;
        display: grid;
        grid-template-columns: 240px 1fr;
        background: rgba(255, 255, 255, 0.72);
      }

      .sidebar {
        background: linear-gradient(180deg, #0d2138 0%, #132d4a 100%);
        color: #e2e8f0;
        padding: 24px;
      }

      .brand {
        font-size: 30px;
        font-weight: 800;
        letter-spacing: 0.04em;
      }

      .nav {
        margin-top: 28px;
        display: grid;
        gap: 12px;
      }

      .nav-item {
        border-radius: 14px;
        padding: 14px 16px;
        color: rgba(226, 232, 240, 0.82);
        background: transparent;
        font-weight: 600;
      }

      .nav-item.active {
        background: rgba(16, 185, 129, 0.18);
        color: #ffffff;
      }

      .nav-footer {
        position: absolute;
        bottom: 24px;
        left: 24px;
        right: 24px;
        color: rgba(226, 232, 240, 0.72);
        font-size: 14px;
      }

      .main {
        padding: 24px 28px 28px;
      }

      .topbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 18px;
      }

      .title h1 {
        margin: 0;
        font-size: 36px;
        line-height: 1.1;
      }

      .title p {
        margin: 8px 0 0;
        color: var(--muted);
        font-size: 16px;
      }

      .actions {
        display: flex;
        gap: 10px;
      }

      .btn {
        padding: 11px 16px;
        border-radius: 999px;
        border: 1px solid var(--line);
        background: var(--panel);
        color: var(--text);
        font-size: 14px;
        font-weight: 700;
      }

      .hero {
        border: 1px solid #b7e4d1;
        background: linear-gradient(180deg, #f2fcf7 0%, #e8faf1 100%);
        border-radius: 22px;
        padding: 22px 24px;
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        gap: 18px;
      }

      .hero h2 {
        margin: 0;
        font-size: 24px;
      }

      .hero p, .hero li {
        color: #24554a;
      }

      .grid {
        display: grid;
        gap: 16px;
      }

      .grid.cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .grid.cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .grid.main-content { margin-top: 18px; grid-template-columns: 1.35fr 0.95fr; align-items: start; }

      .card {
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: 22px;
        padding: 18px 20px;
      }

      .card h3 {
        margin: 0 0 6px;
        font-size: 18px;
      }

      .label {
        color: var(--muted);
        font-size: 13px;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        font-weight: 700;
      }

      .row {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        margin-top: 10px;
      }

      .pill {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 7px 12px;
        border-radius: 999px;
        font-size: 13px;
        font-weight: 700;
      }

      .pill.green {
        background: #dcfce7;
        color: #166534;
      }

      .pill.slate {
        background: #edf2f7;
        color: #334155;
      }

      .pill.amber {
        background: #fef3c7;
        color: #92400e;
      }

      .soft {
        background: var(--panel-soft);
      }

      .muted {
        color: var(--muted);
      }

      .list {
        margin: 10px 0 0;
        padding-left: 18px;
        color: var(--muted);
        line-height: 1.6;
      }

      .profile {
        margin-top: 14px;
        border: 1px solid var(--line);
        border-radius: 18px;
        padding: 16px;
      }

      .profile-head {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 12px;
      }

      .profile-title {
        font-size: 20px;
        font-weight: 800;
      }

      .profile-meta {
        margin-top: 6px;
        color: var(--muted);
        font-size: 14px;
      }

      .profile-actions {
        margin-top: 14px;
        display: flex;
        justify-content: flex-end;
        gap: 10px;
      }

      .setup-note {
        background: linear-gradient(180deg, #fffaf0 0%, #fff7ed 100%);
        border: 1px solid #fed7aa;
        color: #9a3412;
        border-radius: 18px;
        padding: 14px 16px;
        font-size: 14px;
        line-height: 1.5;
      }

      .dialog-wrap {
        width: 1500px;
        height: 860px;
        display: grid;
        place-items: center;
        background: radial-gradient(circle at top, rgba(16, 37, 63, 0.08), transparent 32%), #e9eef5;
      }

      .dialog-backdrop {
        position: absolute;
        inset: 0;
        background: rgba(15, 23, 42, 0.14);
      }

      .dialog {
        position: relative;
        width: 860px;
        border-radius: 28px;
        background: var(--panel);
        border: 1px solid var(--line);
        box-shadow: 0 26px 70px rgba(15, 23, 42, 0.18);
        padding: 24px;
      }

      .dialog h1 {
        margin: 0;
        font-size: 34px;
      }

      .dialog p {
        margin: 8px 0 0;
        color: var(--muted);
        line-height: 1.55;
      }

      .status-card {
        margin-top: 18px;
        padding: 16px 18px;
        border-radius: 18px;
        border: 1px solid #b7e4d1;
        background: #eefbf4;
      }

      .status-card h2 {
        margin: 0;
        font-size: 18px;
        color: #166534;
      }

      .field-grid {
        margin-top: 18px;
        display: grid;
        gap: 14px;
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }

      .field-grid.single {
        grid-template-columns: minmax(0, 1fr);
      }

      .field {
        display: grid;
        gap: 8px;
      }

      .field label {
        color: var(--slate);
        font-size: 13px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
      }

      .input {
        min-height: 56px;
        border-radius: 16px;
        border: 1px solid var(--line);
        background: var(--panel-soft);
        padding: 16px 18px;
        font-size: 16px;
        color: var(--text);
        display: flex;
        align-items: center;
        justify-content: space-between;
      }

      .summary-box {
        margin-top: 16px;
        padding: 16px;
        border-radius: 18px;
        border: 1px solid var(--line);
        background: var(--panel-soft);
      }

      .summary-box .headline {
        font-size: 18px;
        font-weight: 800;
      }

      .summary-box .text {
        margin-top: 6px;
        color: var(--muted);
        line-height: 1.55;
      }

      .dialog-actions {
        margin-top: 18px;
        display: flex;
        justify-content: space-between;
        align-items: center;
      }

      .btn.primary {
        background: #10b981;
        border-color: #10b981;
        color: #ffffff;
      }

      .progress {
        margin-top: 18px;
        padding: 18px;
        border-radius: 18px;
        border: 1px solid var(--line);
        background: var(--panel-soft);
      }

      .progress-bar {
        margin-top: 14px;
        height: 14px;
        background: #dbe6f2;
        border-radius: 999px;
        overflow: hidden;
      }

      .progress-bar > span {
        display: block;
        height: 100%;
        width: 68%;
        border-radius: 999px;
        background: linear-gradient(90deg, #14b8a6 0%, #10b981 100%);
      }

      .table {
        margin-top: 18px;
        border: 1px solid var(--line);
        border-radius: 18px;
        overflow: hidden;
      }

      .table-row {
        display: grid;
        grid-template-columns: 1.4fr 0.9fr 0.8fr;
        gap: 12px;
        padding: 15px 18px;
        border-top: 1px solid var(--line);
        background: var(--panel);
        align-items: center;
      }

      .table-row:first-child {
        border-top: none;
        background: #f8fbff;
        font-size: 13px;
        color: var(--muted);
        text-transform: uppercase;
        letter-spacing: 0.06em;
        font-weight: 800;
      }

      .success-toast {
        position: absolute;
        right: 34px;
        bottom: 110px;
        width: 280px;
        border-radius: 18px;
        padding: 16px 18px;
        background: #ffffff;
        border: 1px solid var(--line);
        box-shadow: 0 20px 40px rgba(15, 23, 42, 0.12);
      }

      .success-toast strong {
        display: block;
        font-size: 18px;
        margin-bottom: 6px;
      }
    </style>
  </head>
  <body>
    ${subtitle}
    ${content}
  </body>
</html>`;

const diagnosticsMarkup = () =>
  shell(
    "Printer Setup & Support",
    "",
    `
      <div class="frame">
        <aside class="sidebar">
          <div class="brand">MSCQR</div>
          <div class="nav">
            <div class="nav-item">Dashboard</div>
            <div class="nav-item active">Batches</div>
            <div class="nav-item">QR Tracking</div>
            <div class="nav-item">Audit Logs</div>
          </div>
          <div class="nav-footer">Manufacturer User</div>
        </aside>
        <main class="main">
          <div class="topbar">
            <div class="title">
              <h1>Printer Setup &amp; Support</h1>
              <p>Review printer readiness, guided setup steps, and support-safe status summaries for this workstation.</p>
            </div>
            <div class="actions">
              <div class="btn">Refresh status</div>
              <div class="btn">Copy support summary</div>
              <div class="btn">Open batches</div>
            </div>
          </div>

          <section class="hero">
            <div>
              <div class="pill green">Ready for printing</div>
              <h2 style="margin-top: 14px;">Workstation and saved printer checks are complete.</h2>
              <p>The selected office printer is ready, and the setup page is showing business-safe guidance only.</p>
            </div>
            <div class="grid" style="min-width: 260px;">
              <div class="card soft">
                <div class="label">Connector</div>
                <div style="margin-top: 8px; font-size: 20px; font-weight: 800;">Online</div>
              </div>
              <div class="card soft">
                <div class="label">Selected printer</div>
                <div style="margin-top: 8px; font-size: 18px; font-weight: 800;">Canon TS4100i series 2</div>
              </div>
            </div>
          </section>

          <div class="grid cols-3" style="margin-top: 16px;">
            <div class="card">
              <h3>Workstation connector</h3>
              <div class="row"><span class="muted">Reachable</span><span class="pill green">Yes</span></div>
              <div class="row"><span class="muted">Connected</span><span class="pill green">Yes</span></div>
              <div class="row"><span class="muted">Status note</span><span class="muted">Connector is available.</span></div>
            </div>
            <div class="card">
              <h3>Cloud connection</h3>
              <div class="row"><span class="muted">Status</span><span class="pill green">Ready</span></div>
              <div class="row"><span class="muted">Last update</span><span class="muted">a few seconds ago</span></div>
              <div class="row"><span class="muted">What to know</span><span class="muted">MSCQR will keep this status updated automatically.</span></div>
            </div>
            <div class="card">
              <h3>Next steps</h3>
              <ul class="list">
                <li>Use a saved printer profile for printing.</li>
                <li>Run Check after changing a managed printer setup.</li>
                <li>Copy the support summary if anything needs escalation.</li>
              </ul>
            </div>
          </div>

          <div class="grid main-content">
            <div class="card">
              <h3>Registered printer profiles</h3>
              <div class="profile">
                <div class="profile-head">
                  <div>
                    <div class="profile-title">Canon TS4100i series 2</div>
                    <div class="profile-meta">Office / AirPrint printer · Canon TS4100i series</div>
                  </div>
                  <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                    <span class="pill slate">Office / AirPrint printer</span>
                    <span class="pill green">Active</span>
                    <span class="pill slate">Ready</span>
                  </div>
                </div>
                <div class="profile-meta" style="margin-top: 12px;">This saved office printer is ready for standards-based PDF jobs over the approved route.</div>
                <div class="profile-actions">
                  <div class="btn">Check</div>
                  <div class="btn">Edit</div>
                </div>
              </div>
            </div>

            <div class="grid" style="gap: 16px;">
              <div class="card">
                <h3>Printer compatibility matrix</h3>
                <div class="grid cols-3" style="margin-top: 12px;">
                  <div class="card soft" style="padding: 14px;">
                    <div class="label">LOCAL_AGENT</div>
                    <div style="margin-top: 8px; font-weight: 700;">USB and workstation printers</div>
                  </div>
                  <div class="card soft" style="padding: 14px;">
                    <div class="label">NETWORK_DIRECT</div>
                    <div style="margin-top: 8px; font-weight: 700;">Factory label printers</div>
                  </div>
                  <div class="card soft" style="padding: 14px;">
                    <div class="label">NETWORK_IPP</div>
                    <div style="margin-top: 8px; font-weight: 700;">Office / AirPrint printers</div>
                  </div>
                </div>
              </div>

              <div class="card">
                <h3>Managed printer setup</h3>
                <div class="setup-note">Use this area only when adding or updating a saved factory label printer or office printer profile. Everyday printing stays in the batch workflow.</div>
                <div class="profile-meta" style="margin-top: 14px;">Open setup only when you need to add, edit, or recheck a managed printer profile.</div>
              </div>
            </div>
          </div>
        </main>
      </div>
    `
  );

const createJobMarkup = () =>
  shell(
    "Create Print Job",
    `<div class="dialog-backdrop"></div>`,
    `
      <div class="dialog-wrap">
        <div class="dialog">
          <h1>Create Print Job</h1>
          <p>Select quantity and a saved printer profile. MSCQR keeps the print route tied to the approved setup.</p>

          <div class="status-card">
            <h2>Office printer ready</h2>
            <p>Canon TS4100i series 2 has been checked and is ready for the next approved batch.</p>
          </div>

          <div class="summary-box">
            <div class="headline">March Packaging Run → Canon TS4100i series 2</div>
            <div class="text">Approved labels remain server-controlled. Start print only when the saved printer summary matches the target device.</div>
          </div>

          <div class="field-grid single">
            <div class="field">
              <label>Quantity to print</label>
              <div class="input"><span>50</span><span class="muted">Ready to print: 68</span></div>
            </div>
          </div>

          <div class="field-grid">
            <div class="field">
              <label>Registered printer profile</label>
              <div class="input"><span>Canon TS4100i series 2</span><span class="muted">Saved</span></div>
            </div>
            <div class="field">
              <label>Dispatch route</label>
              <div class="input"><span>Office / AirPrint printer</span><span class="pill green">Ready</span></div>
            </div>
          </div>

          <div class="summary-box">
            <div class="headline">Saved printer summary</div>
            <div class="text">Office / AirPrint printer, backend-direct route, last checked successfully. Open Printer Setup if the saved setup needs to be reviewed before the next run.</div>
          </div>

          <div class="dialog-actions">
            <div class="btn">Open Printer Setup</div>
            <div class="btn primary">Start print</div>
          </div>
        </div>
      </div>
    `
  );

const printStatusMarkup = () =>
  shell(
    "Print Status",
    `<div class="dialog-backdrop"></div>`,
    `
      <div class="dialog-wrap">
        <div class="dialog">
          <h1>Printing Status</h1>
          <p>MSCQR is processing approved labels through the saved printer route.</p>

          <div class="progress">
            <div style="display: flex; justify-content: space-between; gap: 12px; align-items: center;">
              <div>
                <div class="pill amber">In progress</div>
                <div style="margin-top: 12px; font-size: 22px; font-weight: 800;">34 of 50 labels confirmed</div>
                <div class="muted" style="margin-top: 6px;">Sending to saved office printer</div>
              </div>
              <div class="pill slate">Canon TS4100i series 2</div>
            </div>
            <div class="progress-bar"><span></span></div>
          </div>

          <div class="table">
            <div class="table-row">
              <div>Printer</div>
              <div>Status</div>
              <div>Printed</div>
            </div>
            <div class="table-row">
              <div>Canon TS4100i series 2</div>
              <div><span class="pill green">Completed</span></div>
              <div>20 labels</div>
            </div>
            <div class="table-row">
              <div>Canon TS4100i series 2</div>
              <div><span class="pill amber">In progress</span></div>
              <div>34 labels</div>
            </div>
          </div>

          <div class="summary-box">
            <div class="headline">Recent print jobs</div>
            <div class="text">Use this area to confirm that counts are increasing and that the saved printer is reporting progress. If the run pauses, return to Printer Setup and copy the support summary.</div>
          </div>

          <div class="dialog-actions">
            <div class="btn">Open Printer Setup</div>
            <div class="btn primary">Close</div>
          </div>

          <div class="success-toast">
            <strong>Print progress updated</strong>
            34 labels have been confirmed by the server so far.
          </div>
        </div>
      </div>
    `
  );

const captures = [
  { filename: "manufacturer-printer-diagnostics.png", html: diagnosticsMarkup() },
  { filename: "manufacturer-create-print-job.png", html: createJobMarkup() },
  { filename: "manufacturer-print-status.png", html: printStatusMarkup() },
];

async function main() {
  fs.mkdirSync(outDir, { recursive: true });
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1500, height: 860 }, deviceScaleFactor: 1 });

  for (const capture of captures) {
    await page.setContent(capture.html, { waitUntil: "load" });
    await page.screenshot({ path: path.join(outDir, capture.filename) });
  }

  await browser.close();
  console.log(`Generated ${captures.length} printing illustrations in ${path.relative(repoRoot, outDir)}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
