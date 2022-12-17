package dev.whyoleg.cryptography.webcrypto.external

import org.khronos.webgl.*

internal external interface CryptoKey {
    val type: String // "secret", "private", "public"
    val extractable: Boolean
    val algorithm: KeyAlgorithm
    val usages: Array<String> // "encrypt" | "decrypt" | "sign" | "verify" | "deriveKey" | "deriveBits" | "wrapKey" | "unwrapKey"
}

internal external interface CryptoKeyPair {
    val privateKey: CryptoKey
    val publicKey: CryptoKey
}

internal external interface KeyAlgorithm {
    var name: String
}

internal external interface SymmetricKeyAlgorithm : KeyAlgorithm
internal external interface AsymmetricKeyAlgorithm : KeyAlgorithm

internal external interface AesKeyAlgorithm : SymmetricKeyAlgorithm {
    var length: Int
}

internal external interface RsaHashedKeyGenParams : AsymmetricKeyAlgorithm {
    var modulusLength: Int
    var publicExponent: Uint8Array
    var hash: String
}

internal inline fun AesCtrKeyAlgorithm(block: AesKeyAlgorithm.() -> Unit = {}): AesKeyAlgorithm =
    KeyAlgorithm("AES-CTR", block)

internal inline fun AesGcmKeyAlgorithm(block: AesKeyAlgorithm.() -> Unit = {}): AesKeyAlgorithm =
    KeyAlgorithm("AES-GCM", block)

internal inline fun RsaOaepKeyGenParams(block: RsaHashedKeyGenParams.() -> Unit = {}): RsaHashedKeyGenParams =
    KeyAlgorithm("RSA-OAEP", block)

private inline fun <T : KeyAlgorithm> KeyAlgorithm(name: String, block: T.() -> Unit): T =
    js("{}").unsafeCast<T>().apply {
        this.name = name
        block()
    }
