"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildScanUrl = exports.verifyQrToken = exports.signQrPayload = exports.hashToken = exports.randomNonce = void 0;
const crypto_1 = require("crypto");
const toBase64Url = (buf) => buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
const fromBase64Url = (input) => {
    const padded = input.replace(/-/g, "+").replace(/_/g, "/");
    const pad = padded.length % 4;
    const withPad = pad ? padded + "=".repeat(4 - pad) : padded;
    return Buffer.from(withPad, "base64");
};
const decodeBase64UrlStrict = (input) => {
    if (!/^[A-Za-z0-9_-]+$/.test(input)) {
        throw new Error("Invalid token encoding");
    }
    const buf = fromBase64Url(input);
    // Reject non-canonical variants so mutated tokens cannot decode to the same bytes.
    if (toBase64Url(buf) !== input) {
        throw new Error("Invalid token encoding");
    }
    return buf;
};
const normalizePem = (value) => value.replace(/\\n/g, "\n").trim();
const stableStringify = (obj) => {
    if (obj === null || typeof obj !== "object") {
        return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
        return `[${obj.map((v) => stableStringify(v)).join(",")}]`;
    }
    const keys = Object.keys(obj).sort();
    const body = keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",");
    return `{${body}}`;
};
const getSignMode = () => {
    const priv = process.env.QR_SIGN_PRIVATE_KEY;
    const pub = process.env.QR_SIGN_PUBLIC_KEY;
    if (priv && pub)
        return { mode: "ed25519", key: "ed25519" };
    const hmac = process.env.QR_SIGN_HMAC_SECRET;
    if (hmac)
        return { mode: "hmac", key: "hmac" };
    throw new Error("Missing QR signing keys. Set QR_SIGN_PRIVATE_KEY + QR_SIGN_PUBLIC_KEY (preferred) or QR_SIGN_HMAC_SECRET.");
};
const getEd25519Keys = () => {
    const priv = process.env.QR_SIGN_PRIVATE_KEY;
    const pub = process.env.QR_SIGN_PUBLIC_KEY;
    if (!priv || !pub)
        throw new Error("Missing QR_SIGN_PRIVATE_KEY / QR_SIGN_PUBLIC_KEY");
    const privateKey = (0, crypto_1.createPrivateKey)(normalizePem(priv));
    const publicKey = (0, crypto_1.createPublicKey)(normalizePem(pub));
    return { privateKey, publicKey };
};
const randomNonce = () => (0, crypto_1.randomBytes)(16).toString("base64url");
exports.randomNonce = randomNonce;
const hashToken = (token) => (0, crypto_1.createHash)("sha256").update(token).digest("hex");
exports.hashToken = hashToken;
const signQrPayload = (payload) => {
    const sanitized = {};
    for (const [k, v] of Object.entries(payload)) {
        if (v !== undefined)
            sanitized[k] = v;
    }
    const payloadJson = stableStringify(sanitized);
    const payloadBuf = Buffer.from(payloadJson, "utf8");
    const payloadHash = (0, crypto_1.createHash)("sha256").update(payloadBuf).digest();
    const { mode } = getSignMode();
    let sig;
    if (mode === "ed25519") {
        const { privateKey } = getEd25519Keys();
        sig = (0, crypto_1.sign)(null, payloadHash, privateKey);
    }
    else {
        const secret = String(process.env.QR_SIGN_HMAC_SECRET || "");
        sig = (0, crypto_1.createHmac)("sha256", secret).update(payloadHash).digest();
    }
    return `${toBase64Url(payloadBuf)}.${toBase64Url(sig)}`;
};
exports.signQrPayload = signQrPayload;
const verifyQrToken = (token) => {
    const tokenStr = String(token || "").trim();
    const parts = tokenStr.split(".");
    if (parts.length !== 2)
        throw new Error("Invalid token format");
    const [payloadPart, sigPart] = parts;
    if (!payloadPart || !sigPart)
        throw new Error("Invalid token format");
    const payloadBuf = decodeBase64UrlStrict(payloadPart);
    const payloadJson = payloadBuf.toString("utf8");
    const payload = JSON.parse(payloadJson);
    const payloadHash = (0, crypto_1.createHash)("sha256").update(payloadBuf).digest();
    const { mode } = getSignMode();
    if (mode === "ed25519") {
        const { publicKey } = getEd25519Keys();
        const ok = (0, crypto_1.verify)(null, payloadHash, publicKey, decodeBase64UrlStrict(sigPart));
        if (!ok)
            throw new Error("Signature verification failed");
    }
    else {
        const secret = String(process.env.QR_SIGN_HMAC_SECRET || "");
        const expected = (0, crypto_1.createHmac)("sha256", secret).update(payloadHash).digest();
        const got = decodeBase64UrlStrict(sigPart);
        if (expected.length !== got.length || !(0, crypto_1.timingSafeEqual)(expected, got)) {
            throw new Error("Signature verification failed");
        }
    }
    return { payload };
};
exports.verifyQrToken = verifyQrToken;
const buildScanUrl = (token) => {
    const base = String(process.env.PUBLIC_SCAN_WEB_BASE_URL || "").trim() ||
        String(process.env.PUBLIC_VERIFY_WEB_BASE_URL || "").trim() ||
        String(process.env.CORS_ORIGIN || "").trim() ||
        "http://localhost:8080";
    const normalized = base.replace(/\/+$/, "");
    return `${normalized}/scan?t=${encodeURIComponent(token)}`;
};
exports.buildScanUrl = buildScanUrl;
//# sourceMappingURL=qrTokenService.js.map