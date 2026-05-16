#!/usr/bin/env node

const dns = require("dns").promises;

const domain = String(process.env.EMAIL_DOMAIN || "mscqr.com").trim().toLowerCase();
const selector = String(process.env.EMAIL_DKIM_SELECTOR || "").trim().toLowerCase();

const print = (level, message, details) => {
  const suffix = details ? ` ${JSON.stringify(details)}` : "";
  console.log(`[${level}] ${message}${suffix}`);
};

const txtRecords = async (name) => {
  try {
    return (await dns.resolveTxt(name)).map((parts) => parts.join(""));
  } catch (error) {
    if (["ENOTFOUND", "ENODATA"].includes(String(error?.code || ""))) return [];
    throw error;
  }
};

const cnameRecords = async (name) => {
  try {
    return await dns.resolveCname(name);
  } catch (error) {
    if (["ENOTFOUND", "ENODATA"].includes(String(error?.code || ""))) return [];
    throw error;
  }
};

(async () => {
  print("INFO", `Checking email DNS for ${domain}`);

  const spf = (await txtRecords(domain)).filter((record) => record.toLowerCase().startsWith("v=spf1"));
  if (spf.length === 0) {
    print("FAIL", "SPF record not found", { name: domain });
  } else if (spf.some((record) => record.includes("spf.privateemail.com"))) {
    print("PASS", "SPF record includes Namecheap Private Email", { count: spf.length });
  } else {
    print("WARN", "SPF record exists but does not include spf.privateemail.com; verify provider guidance", { count: spf.length });
  }

  const dmarcName = `_dmarc.${domain}`;
  const dmarc = (await txtRecords(dmarcName)).filter((record) => record.toLowerCase().startsWith("v=dmarc1"));
  if (dmarc.length === 0) {
    print("WARN", "DMARC record not found", { name: dmarcName });
  } else {
    print("PASS", "DMARC record found", { name: dmarcName, count: dmarc.length });
  }

  if (!selector) {
    print("WARN", "DKIM selector not configured. Verify in Namecheap Private Email and Gmail Show original.");
  } else {
    const dkimName = `${selector}._domainkey.${domain}`;
    const dkimTxt = await txtRecords(dkimName);
    const dkimCname = await cnameRecords(dkimName);
    if (dkimTxt.length || dkimCname.length) {
      print("PASS", "DKIM selector record found", { name: dkimName, txtCount: dkimTxt.length, cnameCount: dkimCname.length });
    } else {
      print("WARN", "DKIM selector record not found", { name: dkimName });
    }
  }
})().catch((error) => {
  print("FAIL", "Email DNS check failed", { error: error instanceof Error ? error.message : "Unknown error" });
  process.exit(1);
});
