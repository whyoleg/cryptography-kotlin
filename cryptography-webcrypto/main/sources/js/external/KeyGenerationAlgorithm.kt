package dev.whyoleg.cryptography.webcrypto.external

import org.khronos.webgl.*

internal sealed external interface KeyGenerationAlgorithm : Algorithm
internal sealed external interface SymmetricKeyGenerationAlgorithm : KeyGenerationAlgorithm
internal sealed external interface AsymmetricKeyGenerationAlgorithm : KeyGenerationAlgorithm

internal sealed external interface HmacKeyGenerationAlgorithm : SymmetricKeyGenerationAlgorithm {
    var hash: String
//    var length: Int //TODO - is it needed?
}

internal fun HmacKeyGenerationAlgorithm(hash: String): HmacKeyGenerationAlgorithm = Algorithm("HMAC") {
    this.hash = hash
}

internal external interface AesKeyGenerationAlgorithm : SymmetricKeyGenerationAlgorithm {
    var length: Int
}

internal fun AesKeyGenerationAlgorithm(name: String, length: Int): AesKeyGenerationAlgorithm =
    Algorithm(name) {
        this.length = length
    }

internal external interface RsaHashedKeyGenerationAlgorithm : AsymmetricKeyGenerationAlgorithm {
    var modulusLength: Int
    var publicExponent: Uint8Array
    var hash: String
}

internal inline fun RsaHashedKeyGenerationAlgorithm(block: RsaHashedKeyGenerationAlgorithm.() -> Unit = {}): RsaHashedKeyGenerationAlgorithm =
    Algorithm("RSA-OAEP", block)
