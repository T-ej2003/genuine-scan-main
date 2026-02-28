export const PREMIUM_PALETTE = {
  mist: "#bccad6",
  steel: "#8d9db6",
  anchor: "#667292",
  warm: "#f1e3dd",
} as const;

export const premiumGradient = `linear-gradient(140deg, ${PREMIUM_PALETTE.warm} 0%, #ffffff 38%, ${PREMIUM_PALETTE.mist} 100%)`;
