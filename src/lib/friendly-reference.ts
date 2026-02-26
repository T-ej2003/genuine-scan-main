const ADJECTIVES = [
  "Amber",
  "Arctic",
  "Azure",
  "Bold",
  "Bright",
  "Calm",
  "Cedar",
  "Clear",
  "Coral",
  "Crisp",
  "Delta",
  "Echo",
  "Emerald",
  "Falcon",
  "Forest",
  "Golden",
  "Harbor",
  "Ivory",
  "Jade",
  "Lunar",
  "Maple",
  "Misty",
  "North",
  "Nova",
  "Ocean",
  "Olive",
  "Onyx",
  "Prime",
  "Quartz",
  "Royal",
  "Silver",
  "Solar",
  "Stone",
  "Swift",
  "Urban",
  "Vivid",
];

const NOUNS = [
  "Anchor",
  "Beacon",
  "Bridge",
  "Case",
  "Crest",
  "Drift",
  "Field",
  "Flare",
  "Frame",
  "Gate",
  "Glade",
  "Guide",
  "Harbor",
  "Horizon",
  "Index",
  "Lane",
  "Leaf",
  "Mark",
  "Matrix",
  "Path",
  "Peak",
  "Point",
  "Pulse",
  "Range",
  "Ridge",
  "Scope",
  "Signal",
  "Source",
  "Spark",
  "Stream",
  "Track",
  "Trail",
  "Vault",
  "Vector",
  "Wave",
  "Wing",
];

const hashString = (input: string) => {
  let h = 2166136261;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
};

export const friendlyReferenceWords = (value: string, count: 1 | 2 = 2) => {
  const raw = String(value || "").trim();
  if (!raw) return count === 1 ? "Ref" : "Clear Mark";
  const h = hashString(raw);
  const a = ADJECTIVES[h % ADJECTIVES.length];
  const b = NOUNS[((h >>> 8) ^ h) % NOUNS.length];
  return count === 1 ? b : `${a} ${b}`;
};

export const friendlyReferenceLabel = (value: string, prefix = "Ref") => {
  const words = friendlyReferenceWords(value, 2);
  return `${prefix} ${words}`;
};

export const shortRawReference = (value: string, size = 8) => {
  const raw = String(value || "").trim();
  if (!raw) return "";
  return raw.length > size ? raw.slice(0, size) : raw;
};

export const looksOpaqueReference = (value: string) => {
  const raw = String(value || "").trim();
  if (!raw) return false;
  return (
    /^[0-9a-f]{8}$/i.test(raw) ||
    /^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(raw) ||
    /^[A-Z]{2,6}-[A-Z0-9]{6,}$/i.test(raw) ||
    /^[A-Z]{1,4}\d{8,}$/i.test(raw)
  );
};
