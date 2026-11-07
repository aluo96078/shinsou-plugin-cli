/**
 * Misleading-name guard. Shinsou has no "official" plugins: every package is third-party, so no
 * package, source or publisher name may claim to be official. Matching is case-insensitive and
 * ignores full-/half-width differences, diacritics, zero-width characters, common digit
 * look-alikes and the separators `_ - . space`.
 */

const BLOCKED_TERMS = [
  "official",
  "offical",
  "oficial",
  "officiel",
  "offiziell",
  "官方",
  "官網",
  "官网",
  "公式", // Japanese 「公式」 = official
];

/**
 * Explicit disclaimers are fine (the app allows them too): they are removed before the blocked
 * terms are searched, and anything left over still counts ("Unofficial Official" is refused).
 */
const DISCLAIMERS = ["unofficial", "unoffical", "nonofficial", "非官方", "非公式"];

const LOOKALIKES: Record<string, string> = { "0": "o", "1": "i", "!": "i", "|": "i", "$": "s", "3": "e", "@": "a" };

export function normalizeForNameCheck(value: string): string {
  let s = value.normalize("NFKC").normalize("NFKD").replace(/\p{M}/gu, "");
  s = s.toLowerCase();
  s = s.replace(/[\u200b-\u200f\u2060\ufeff\u00ad]/g, "");
  s = s.replace(/[\s_\-.\u00b7\u30fb\uff65]+/g, "");
  return [...s].map((c) => LOOKALIKES[c] ?? c).join("");
}

/** The blocked term [value] contains, or null. */
export function misleadingTerm(value: string): string | null {
  let n = normalizeForNameCheck(value);
  for (const d of DISCLAIMERS) n = n.split(normalizeForNameCheck(d)).join(" ");
  for (const term of BLOCKED_TERMS) {
    if (n.includes(normalizeForNameCheck(term))) return term;
  }
  // "offic1al" style substitutions where 1 → i already handled; also catch "0ffi" + "cial" splits.
  if (/of+i?ci?al/.test(n)) return "official";
  return null;
}
