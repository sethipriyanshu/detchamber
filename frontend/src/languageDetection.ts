export type DetectedLanguage =
  | "python"
  | "javascript"
  | "typescript"
  | "java"
  | "go"
  | "rust"
  | "cpp"
  | "sql"
  | "unknown";

export interface LanguageDetectionResult {
  language: DetectedLanguage;
  confidence: number;
  matches: number;
}

interface Signature {
  language: DetectedLanguage;
  patterns: RegExp[];
}

const SIGNATURES: Signature[] = [
  {
    language: "python",
    patterns: [/^\s*def\s+\w+\s*\(/m, /^\s*import\s+\w+/m, /#/m, /print\s*\(/m]
  },
  {
    language: "javascript",
    patterns: [/^\s*(const|let|var)\s+\w+\s*=/m, /function\s+\w+\s*\(/m, /=>\s*{/m]
  },
  {
    language: "typescript",
    patterns: [/:?\s*\w+<\w+>/m, /interface\s+\w+/m]
  },
  {
    language: "java",
    patterns: [/public\s+class\s+\w+/, /void\s+main\s*\(/]
  },
  {
    language: "go",
    patterns: [/^\s*package\s+main/m, /^\s*func\s+\w+\s*\(/m]
  },
  {
    language: "rust",
    patterns: [/^\s*fn\s+\w+\s*\(/m, /\blet\s+mut\s+\w+/m]
  },
  {
    language: "cpp",
    patterns: [/^\s*#include\s+</m, /\bint\s+main\s*\(/m]
  },
  {
    language: "sql",
    patterns: [/\bSELECT\b/i, /\bINSERT\b/i, /\bFROM\b/i]
  }
];

export function detectLanguage(code: string): LanguageDetectionResult {
  if (!code.trim()) {
    return { language: "unknown", confidence: 0, matches: 0 };
  }

  let best: DetectedLanguage = "unknown";
  let bestMatches = 0;

  for (const sig of SIGNATURES) {
    let matches = 0;
    for (const rx of sig.patterns) {
      if (rx.test(code)) {
        matches += 1;
      }
    }
    if (matches > bestMatches) {
      bestMatches = matches;
      best = sig.language;
    }
  }

  const confidence =
    best === "unknown" ? 0 : Math.min(1, bestMatches / 4); // rough heuristic

  return {
    language: best,
    confidence,
    matches: bestMatches
  };
}

