type CaptchaResult = {
  ok: boolean;
  reason?: string;
};

const enabled = () => String(process.env.INCIDENT_CAPTCHA_ENABLED || "false").toLowerCase() === "true";

export const verifyCaptchaToken = async (token?: string | null, remoteIp?: string | null): Promise<CaptchaResult> => {
  if (!enabled()) return { ok: true };

  const trimmedToken = String(token || "").trim();
  if (!trimmedToken) return { ok: false, reason: "Missing captcha token" };

  const bypassToken = String(process.env.INCIDENT_CAPTCHA_BYPASS_TOKEN || "").trim();
  if (bypassToken && bypassToken === trimmedToken) {
    return { ok: true };
  }

  const secret = String(process.env.RECAPTCHA_SECRET_KEY || "").trim();
  if (!secret) return { ok: false, reason: "Captcha secret is not configured" };

  const params = new URLSearchParams();
  params.append("secret", secret);
  params.append("response", trimmedToken);
  if (remoteIp) params.append("remoteip", String(remoteIp));

  try {
    const resp = await fetch("https://www.google.com/recaptcha/api/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });

    if (!resp.ok) return { ok: false, reason: `Captcha verification HTTP ${resp.status}` };
    const data: any = await resp.json().catch(() => null);
    if (!data || data.success !== true) {
      return { ok: false, reason: "Captcha verification failed" };
    }
    return { ok: true };
  } catch (error: any) {
    return { ok: false, reason: error?.message || "Captcha verification failed" };
  }
};
