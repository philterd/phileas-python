# Phileas (Python) Release Notes

Notable changes to the `phileas-redact` package, most recent first.

## Version 1.1.0

* The `age` filter now accepts `=` and `-` as separators between an `age`/`aged` keyword and its value, alongside the colon it already allowed, so `Age = 47` and `Age - 47` are detected as well as `Age: 47`, `Age : 47`, `age:47`, and `Age 47`. This matches the separator set Phileas (Java) settled on, so a policy behaves the same whichever language runs it. The keyword is still required, so a date such as `2026-01-15` is not detected as an age.
* The `ipAddress` filter now detects an IPv6 address in full instead of stopping at the `::` compression. A single IPv6 pattern replaces the previous pair and covers the expanded, compressed, mixed, and IPv4-mapped forms along with a zone identifier (`fe80::1%eth0`); a leading-`::` address such as `::1` is detected now, where before it was not detected at all. The filter also drops overlapping spans before returning, so one address produces one span rather than several truncated ones. This is the parity port of the Phileas (Java) fix.
* The `phEye` filter now performs local, on-device GLiNER inference when `phEyeConfiguration.modelPath` points at a local model directory (the exported ONNX model, its tokenizer, and the GLiNER config). Local inference runs offline with no remote endpoint call, and takes precedence over `endpoint` when both are set. `labels` is the GLiNER detection prompt, and a single `threshold` (default `0.5`) is the minimum span confidence, with per-label `thresholds` still supported for back-compat. This matches the redaction policy schema 1.1.0 `phEyeConfiguration` contract and what PhiSQL's `DETECT PHEYE ... MODEL '<path>'` compiles to. The `gliner` dependency remains an optional extra, and the previous separate `vocabPath` requirement is removed.
* The custom `identifier` filter now supports an optional `validator`. The validator runs a named, built-in check on each regex match and keeps the match only if the check passes, so a generic identifier can reject format-valid but checksum-invalid values without embedding any executable code in the policy. The validator may be written as a string (`"validator": "luhn"`) or as an object with a `name` and optional `params`. An unknown or not-yet-implemented validator name is a policy error rather than being silently ignored. This is the parity port of the Phileas (Java) validator field and requires redaction policy schema 1.1.0.
* Added the `luhn` identifier validator (standard mod-10 Luhn checksum), a parity port of the Phileas (Java) implementation.
* Added the `mod11` identifier validator (weighted-sum mod-11 check digits) with `cpf` and `cnpj` variants for the Brazilian CPF and CNPJ.
* Added the `mod97` identifier validator (control derived from the value mod 97) with `iban` and `nir` variants (the French INSEE/NIR includes Corsica substitutions).
* Added the `mod23-letter` identifier validator (control letter from a 23-entry table) for the Spanish DNI and NIE.
* Added the `es-cif` identifier validator for the Spanish CIF (organization tax ID).
* Added the `de-steuerid` identifier validator for the German tax ID (Steuer-ID), using the digit-repetition rule and the ISO/IEC 7064 MOD 11,10 check digit.
* Added the `de-personalausweis` identifier validator for the German ID card number (ICAO 9303 7-3-1 check digit).
* Added the `bic-structural` identifier validator for SWIFT/BIC codes (ISO 9362 structure with a valid ISO 3166 country segment).
