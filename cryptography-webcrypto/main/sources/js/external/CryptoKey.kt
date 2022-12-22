package dev.whyoleg.cryptography.webcrypto.external

import org.khronos.webgl.*

internal external interface CryptoKey {
    val type: String // "secret", "private", "public"
    val extractable: Boolean
    val algorithm: KeyGenerationAlgorithm
    val usages: Array<String> // "encrypt" | "decrypt" | "sign" | "verify" | "deriveKey" | "deriveBits" | "wrapKey" | "unwrapKey"
}

internal external interface CryptoKeyPair {
    val privateKey: CryptoKey
    val publicKey: CryptoKey
}

internal sealed external interface AsymmetricKeyGenAlgorithm : KeyGenerationAlgorithm

internal external interface AesKeyGenAlgorithm : SymmetricKeyGenerationAlgorithm {
    var length: Int
}

internal external interface RsaHashedKeyGenParamsGen : AsymmetricKeyGenAlgorithm {
    var modulusLength: Int
    var publicExponent: Uint8Array
    var hash: String
}

internal inline fun AesCtrKeyAlgorithm(block: AesKeyGenAlgorithm.() -> Unit = {}): AesKeyGenAlgorithm =
    KeyAlgorithm("AES-CTR", block)

internal inline fun AesCbcKeyAlgorithm(block: AesKeyGenAlgorithm.() -> Unit = {}): AesKeyGenAlgorithm =
    KeyAlgorithm("AES-CBC", block)

internal inline fun AesGcmKeyAlgorithm(block: AesKeyGenAlgorithm.() -> Unit = {}): AesKeyGenAlgorithm =
    KeyAlgorithm("AES-GCM", block)

internal inline fun RsaOaepKeyGenParams(block: RsaHashedKeyGenParamsGen.() -> Unit = {}): RsaHashedKeyGenParamsGen =
    KeyAlgorithm("RSA-OAEP", block)

private inline fun <T : KeyGenerationAlgorithm> KeyAlgorithm(name: String, block: T.() -> Unit): T =
    js("{}").unsafeCast<T>().apply {
        this.name = name
        block()
    }
