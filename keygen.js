// ── ShadowStore Keygen Core v3 ────────────────────────────────────────
//
// Formato : SHADOW-XXXXXX
// Charset : A-Z + 0-9  (36 chars)
//
// Por qué NO símbolos:
//   • Firebase RTDB prohíbe '#' y '$' en nombres de nodo
//   • '%' sin URL-encode rompe la request REST del módulo nativo
//   • '!@^&*' causan problemas en parsers del mod
//   • A-Z0-9 es 100% Firebase-safe y URL-safe
//
// Garantías de complejidad:
//   • ≥2 letras  (A-Z)
//   • ≥2 dígitos (0-9)
//   • Fisher-Yates con crypto.getRandomValues — sin modulo bias

const ALPHA   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMERIC = "0123456789";
const FULL    = ALPHA + NUMERIC;

/**
 * Cryptographically secure random char — rejection sampling elimina modulo bias.
 */
function secureRand(charset) {
  const cap = Math.floor(0x100000000 / charset.length) * charset.length;
  const buf = new Uint32Array(1);
  let v;
  do { crypto.getRandomValues(buf); v = buf[0]; } while (v >= cap);
  return charset[v % charset.length];
}

/**
 * Fisher-Yates in-place shuffle usando crypto.getRandomValues.
 */
function fisherYates(arr) {
  const buf = new Uint32Array(1);
  for (let i = arr.length - 1; i > 0; i--) {
    crypto.getRandomValues(buf);
    const j = buf[0] % (i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/**
 * Genera una key con formato SHADOW-XXXXXX.
 * Garantiza ≥2 letras y ≥2 dígitos antes de mezclar.
 */
function generateKey() {
  const mandatory = [
    secureRand(ALPHA), secureRand(ALPHA),
    secureRand(NUMERIC), secureRand(NUMERIC)
  ];
  const rest  = [secureRand(FULL), secureRand(FULL)];
  const chars = fisherYates([...mandatory, ...rest]);
  return "SHADOW-" + chars.join("");
}

/**
 * Valida formato de key — debe matchear ka_check_format() en el mod nativo.
 * SHADOW-XXXXXX: prefijo fijo + 6 chars A-Z0-9, ≥2 letras y ≥2 dígitos.
 */
function validateFormat(key) {
  if (!key || typeof key !== "string") return false;
  if (!key.startsWith("SHADOW-"))       return false;
  const suffix = key.slice(7);
  if (suffix.length !== 6)              return false;
  let letters = 0, digits = 0;
  for (const c of suffix) {
    if (c >= "A" && c <= "Z") { letters++; continue; }
    if (c >= "0" && c <= "9") { digits++;  continue; }
    return false;
  }
  return letters >= 2 && digits >= 2;
}

/**
 * Calcula timestamp de expiración desde una clave de duración.
 * @param {string} durKey — "1d" | "7d" | "15d" | "30d"
 * @returns {number} Unix timestamp en ms
 */
function calcExpiry(durKey) {
  return Date.now() + DURATIONS[durKey].days * 86400000;
}
