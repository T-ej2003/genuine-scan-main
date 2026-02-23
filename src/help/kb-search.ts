import { HELP_KB, type HelpKbEntry, type HelpKbRole } from "@/help/kb";

const normalize = (value: string) => value.toLowerCase().trim();
const STOP_WORDS = new Set([
  "a",
  "an",
  "and",
  "are",
  "as",
  "at",
  "be",
  "by",
  "do",
  "for",
  "from",
  "how",
  "i",
  "if",
  "in",
  "is",
  "it",
  "me",
  "my",
  "of",
  "on",
  "or",
  "the",
  "to",
  "was",
  "what",
  "when",
  "where",
  "who",
  "why",
  "with",
]);

const tokenize = (query: string) =>
  normalize(query)
    .split(/[^a-z0-9]+/g)
    .map((token) => token.trim())
    .filter((token) => token.length >= 2 && !STOP_WORDS.has(token));

const roleMatches = (entryRole: HelpKbRole, activeRole: HelpKbRole) => {
  if (entryRole === "all") return true;
  if (activeRole === "all") return true;
  return entryRole === activeRole;
};

const scoreEntry = (entry: HelpKbEntry, query: string, tokens: string[]) => {
  if (!tokens.length) return 0;

  const normalizedQuery = normalize(query);
  const title = normalize(entry.title);
  const answer = normalize(entry.answer);
  const keywords = entry.keywords.map(normalize);
  const searchableWords = new Set(
    `${entry.title} ${entry.keywords.join(" ")}`
      .toLowerCase()
      .split(/[^a-z0-9]+/g)
      .filter(Boolean)
  );

  let score = 0;
  let strongTokenHits = 0;

  if (title.includes(normalizedQuery) || keywords.some((k) => k.includes(normalizedQuery))) {
    score += 28;
  }
  if (normalizedQuery.length >= 3 && answer.includes(normalizedQuery)) {
    score += 8;
  }

  for (const token of tokens) {
    const keywordExact = keywords.includes(token);
    const keywordPartial = keywords.some((k) => k.includes(token) || token.includes(k));
    const titleHit = title.includes(token);
    const answerHit = answer.includes(token);

    if (keywordExact) score += 18;
    if (keywordPartial) score += 10;
    if (titleHit) score += 8;
    if (answerHit) score += 3;

    if (keywordExact || keywordPartial || titleHit) strongTokenHits += 1;

    if (token.length >= 3) {
      const prefix = token.slice(0, 3);
      if (Array.from(searchableWords).some((word) => word.startsWith(prefix))) {
        score += 2;
      }
    }
  }

  const hasStrongQueryMatch =
    title.includes(normalizedQuery) || keywords.some((k) => k.includes(normalizedQuery));

  if (!hasStrongQueryMatch && strongTokenHits === 0) {
    return 0;
  }

  if (tokens.length >= 2) {
    const requiredHits = Math.max(1, Math.ceil(tokens.length / 2));
    if (strongTokenHits < requiredHits) {
      score -= 8;
    }
  }

  return score;
};

export type HelpSearchResult = {
  entry: HelpKbEntry;
  score: number;
  shortAnswer: string;
};

export const getShortAnswer = (answerMarkdown: string) => {
  const firstBlock = answerMarkdown.split(/\n\s*\n/)[0] || answerMarkdown;
  return firstBlock.replace(/\*\*/g, "").trim();
};

export const searchHelpEntries = (query: string, activeRole: HelpKbRole, limit = 3): HelpSearchResult[] => {
  const trimmed = query.trim();
  if (!trimmed) return [];

  const tokens = tokenize(trimmed);
  if (!tokens.length && trimmed.length < 3) return [];
  const activeTokens = tokens.length > 0 ? tokens : [normalize(trimmed)];
  const minScore = activeTokens.length >= 2 ? 12 : 10;

  return HELP_KB.filter((entry) => roleMatches(entry.role, activeRole))
    .map((entry) => {
      const score = scoreEntry(entry, trimmed, activeTokens);
      return {
        entry,
        score,
        shortAnswer: getShortAnswer(entry.answer),
      };
    })
    .filter((hit) => hit.score >= minScore)
    .sort((a, b) => b.score - a.score || a.entry.title.localeCompare(b.entry.title))
    .slice(0, Math.max(limit, 1));
};

export const getEntryById = (id: string): HelpKbEntry | null => {
  const normalizedId = normalize(id);
  return HELP_KB.find((entry) => normalize(entry.id) === normalizedId) || null;
};

export const getFallbackSuggestions = (activeRole: HelpKbRole, count = 4): HelpKbEntry[] => {
  const roleMatchesList = HELP_KB.filter((entry) => roleMatches(entry.role, activeRole));
  const sorted = roleMatchesList.sort((a, b) => a.title.localeCompare(b.title));
  return sorted.slice(0, Math.max(count, 1));
};
