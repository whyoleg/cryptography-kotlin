package dev.whyoleg.cryptography

import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.hash.*
import dev.whyoleg.cryptography.key.*
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

private fun test() {
    with(AES.GCM) {
        val generator = KeyPairGenerator.Async(engine) {
            //parameters
        }

        val keyPair = generator.generateKeyPair()

        val encryptor = Encryptor.Sync(keyPair.publicKey) {
            //parameters
        }
    }

    engine.syncHasher(SHA256)
    engine.syncHasher(SHA512)
    engine.syncHasher(SHA3.B512)
    engine.syncHasher(SHAKE.B128) {
        //parameters
    }


    engine.asyncKeyPairGenerator(EC.P256)
    val generator = engine.syncKeyPairGenerator(EC.P256) {
        //parameters
    }

    //suspend
    val keyPair = generator.generateKey {
        //parameters
    }

    keyPair.privateKey.syncEncryptor {
        //parameters
    }

    val provider: KeyGenerator.Provider


    val generator = provider.syncKeyGenerator(AES.GCM)

    val key = generator.generateKey(SymmetricKeyParameters(SymmetricKeySize.B256))

    val cipher = key.syncCipher(AES.GCM.CipherParameters(128.bits))

    key.syncCipher {
        tagLength = 128.bits
    }

    AES.GCM.CipherParameters(128.bits).copy {
        tagLength = 128.bits
    }

}

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

public class SymmetricKeyParameters(
    public val size: SymmetricKeySize,
)

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
