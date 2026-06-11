# Threat Analysis and Risk Assessment (TARA)

**Standard**: ISO 21434  
**Generated**: 2026-06-11T19:06:56Z  
**Tool**: rust-FuSa 0.2.0  

## Threat Register

| Threat | STRIDE | CWE | Risk | Mitigation | Rule |
|--------|--------|-----|------|------------|------|
| possible hardcoded secret key in string literal | T | CWE-798 | HIGH | load credentials from environment variables or a secrets manager | CYBER001 |
| SQL query appears to be constructed by string interpolation | T | CWE-89 | HIGH | use parameterised queries (? placeholders) instead of string concatenation | CYBER002 |
| SQL query appears to be constructed by string interpolation | T | CWE-89 | HIGH | use parameterised queries (? placeholders) instead of string concatenation | CYBER002 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| path constructed from potentially user-controlled input without canonicalization | T | CWE-22 | HIGH | call .canonicalize() and verify the result is within the allowed root | CYBER003 |
| non-cryptographic RNG — do not use for security-sensitive values | T | CWE-330 | MEDIUM | use OsRng or the rand::rngs::OsRng for cryptographic randomness | CYBER004 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| arithmetic on length/count values without overflow check | T | CWE-190 | MEDIUM | use .checked_add() / .checked_mul() to prevent integer overflow | CYBER005 |
| HTTP URL used — data transmitted in cleartext | I | CWE-319 | HIGH | use HTTPS to encrypt data in transit | CYBER006 |
| HTTP URL used — data transmitted in cleartext | I | CWE-319 | HIGH | use HTTPS to encrypt data in transit | CYBER006 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| allocation with non-constant size — ensure capacity is bounded | D | CWE-400 | MEDIUM | cap allocations with a constant maximum (e.g., .min(MAX_CAPACITY)) | CYBER012 |
| allocation with non-constant size — ensure capacity is bounded | D | CWE-400 | MEDIUM | cap allocations with a constant maximum (e.g., .min(MAX_CAPACITY)) | CYBER012 |
| TLS certificate verification disabled — vulnerable to MITM | T | CWE-295 | HIGH | enable TLS certificate verification; never disable in production code | CYBER013 |
| TLS certificate verification disabled — vulnerable to MITM | T | CWE-295 | HIGH | enable TLS certificate verification; never disable in production code | CYBER013 |
| filesystem check followed by use within 5 lines — possible TOCTOU | T | CWE-367 | MEDIUM | open the file directly and handle errors; avoid separate existence check | CYBER014 |
| filesystem check followed by use within 5 lines — possible TOCTOU | T | CWE-367 | MEDIUM | open the file directly and handle errors; avoid separate existence check | CYBER014 |
| filesystem check followed by use within 5 lines — possible TOCTOU | T | CWE-367 | MEDIUM | open the file directly and handle errors; avoid separate existence check | CYBER014 |
| filesystem check followed by use within 5 lines — possible TOCTOU | T | CWE-367 | MEDIUM | open the file directly and handle errors; avoid separate existence check | CYBER014 |
| filesystem check followed by use within 5 lines — possible TOCTOU | T | CWE-367 | MEDIUM | open the file directly and handle errors; avoid separate existence check | CYBER014 |
| filesystem check followed by use within 5 lines — possible TOCTOU | T | CWE-367 | MEDIUM | open the file directly and handle errors; avoid separate existence check | CYBER014 |
| world-writable/world-readable file permission mask | T | CWE-732 | MEDIUM | use restrictive permissions (e.g., 0o600 for user-only read/write) | CYBER015 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| path .join() with variable argument — verify no .. traversal is possible | T | CWE-22 | MEDIUM | call .canonicalize() after joining and verify path is within allowed root | CYBER017 |
| ManuallyDrop used without //fusa:unsafe justification | T | CWE-415 | HIGH | document why ManuallyDrop is necessary and add //fusa:unsafe justification | CYBER018 |
| ManuallyDrop used without //fusa:unsafe justification | T | CWE-415 | HIGH | document why ManuallyDrop is necessary and add //fusa:unsafe justification | CYBER018 |
| ManuallyDrop used without //fusa:unsafe justification | T | CWE-415 | HIGH | document why ManuallyDrop is necessary and add //fusa:unsafe justification | CYBER018 |
| ManuallyDrop used without //fusa:unsafe justification | T | CWE-415 | HIGH | document why ManuallyDrop is necessary and add //fusa:unsafe justification | CYBER018 |
| ManuallyDrop used without //fusa:unsafe justification | T | CWE-415 | HIGH | document why ManuallyDrop is necessary and add //fusa:unsafe justification | CYBER018 |
| ManuallyDrop used without //fusa:unsafe justification | T | CWE-415 | HIGH | document why ManuallyDrop is necessary and add //fusa:unsafe justification | CYBER018 |
| ManuallyDrop used without //fusa:unsafe justification | T | CWE-415 | HIGH | document why ManuallyDrop is necessary and add //fusa:unsafe justification | CYBER018 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| write!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| write!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| write!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| write!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| write!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| write!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| write!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| write!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| write!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| write!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| write!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| writeln!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| from_utf8_unchecked invoked without //fusa:unsafe justification | T | CWE-20 | HIGH | use std::str::from_utf8() which returns Result; only use unchecked variant with proof of valid UTF-8 | CYBER020 |
| from_utf8_unchecked invoked without //fusa:unsafe justification | T | CWE-20 | HIGH | use std::str::from_utf8() which returns Result; only use unchecked variant with proof of valid UTF-8 | CYBER020 |
| from_utf8_unchecked invoked without //fusa:unsafe justification | T | CWE-20 | HIGH | use std::str::from_utf8() which returns Result; only use unchecked variant with proof of valid UTF-8 | CYBER020 |

## Summary

- Total: 620
- HIGH: 39
- MEDIUM: 581
- LOW: 0
