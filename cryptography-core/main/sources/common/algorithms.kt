package dev.whyoleg.cryptography

import dev.whyoleg.cryptography.signature.*

//need to support ALL algorithms that are shared between:
// - JDK (jvm/android)
// - JS WebCrypto (js) - only async support, small subset of algorithms
// - CoreCrypto (darwin/iOS)
// - CryptoKit (swift) - at least try to use it and check which algorithms are supported
// - OpenSSL (linux)
// - CNG (windows)
// - Rust Crypto - check on supported algorithms
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

//get can be sync and async; primitive can be sync and async

public object EC {
    public object P256 {
        public interface PublicKey

        public fun generateKeyPair(
            parameters: Unit,
        ): KeyPair = TODO()

        public interface PrivateKey {
            public val publicKey: PublicKey

            public fun signer(hasher: Int): SyncSigner
            public fun asyncSigner(hasher: Int): AsyncSigner
        }

        public interface KeyPair {
            public val publicKey: PublicKey
            public val privateKey: PrivateKey
        }
    }
}

public object RSA {
    public object OAEP {
        public interface PublicKey

        public interface PrivateKey {
            public val publicKey: PublicKey
        }

        public interface KeyPair {
            public val publicKey: PublicKey
            public val privateKey: PrivateKey
        }
    }
}
