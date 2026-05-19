import {
  classifyQrSigningSecretFormat,
  validateQrSigningConfiguration,
} from "../services/qrTokenService";

const present = (key: string) => Boolean(String(process.env[key] || "").trim());
const lengthOf = (key: string) => String(process.env[key] || "").length;

const summary = {
  provider: String(process.env.QR_SIGN_PROVIDER || "").trim() || "env",
  activeKeyVersionPresent: present("QR_SIGN_ACTIVE_KEY_VERSION"),
  privateKeyPresent: present("QR_SIGN_PRIVATE_KEY"),
  publicKeyPresent: present("QR_SIGN_PUBLIC_KEY"),
  privateKeyFormat: classifyQrSigningSecretFormat(process.env.QR_SIGN_PRIVATE_KEY),
  publicKeyFormat: classifyQrSigningSecretFormat(process.env.QR_SIGN_PUBLIC_KEY),
  privateKeyLength: lengthOf("QR_SIGN_PRIVATE_KEY"),
  publicKeyLength: lengthOf("QR_SIGN_PUBLIC_KEY"),
};

console.info("qrSigningPreflight", summary);

try {
  const profile = validateQrSigningConfiguration();
  console.info("qrSigningPreflight", {
    status: "ok",
    mode: profile.mode,
    provider: profile.provider,
    keyVersionPresent: Boolean(String(profile.keyVersion || "").trim()),
  });
} catch (error: any) {
  console.error("qrSigningPreflight", {
    status: "failed",
    code: String(error?.code || "").trim() || null,
    cryptoMetadata: error?.safeCryptoMetadata || null,
  });
  process.exit(1);
}
