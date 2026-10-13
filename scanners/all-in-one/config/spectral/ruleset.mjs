// scanX Spectral ruleset: the OWASP API Security Top 10 (2023) ruleset by
// Stoplight. owasp.mjs is the package's own bundle, copied into the image
// from the hash-verified npm tarball; it only imports Spectral built-ins,
// so nothing is resolved or fetched at scan time.
import owasp from "./owasp.mjs";

export default { extends: [owasp] };
