package dev.whyoleg.cryptography.api

//need to support ALL algorithms that are shared between:
// - JDK (jvm/android)
// - JS WebCrypto (js) - only async support, small subset of algorithms
// - CoreCrypto (darwin/iOS)
// - OpenSSL (linux)
// - CNG (windows)
// + some additional popular algorithms that are supported by JDK/OpenSSL

/** Algorithms examples:
 * - encryption/decryption: AES(CTR, CBC, GCM) +, RSA(OAEP)
 * - hash: SHA(1, 2, 3) +, SHAKE(128, 256) +
 * - mac: HMAC(ANY HASH) +, CMAC(AES-CBC) +, GMAC(AES-GCM) +
 * - sing/verify: RSA(SSA, PSS), ECDSA
 * - key wrap/unwrap: AES(all + KW), RSA(OAEP)
 * - derive key: ECDH, HKDF, PBKDF2
 * - importing key formats: RAW, JWK, PKCS-XXX
 */
