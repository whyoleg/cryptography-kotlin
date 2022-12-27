package dev.whyoleg.cryptography.webcrypto.external

internal sealed external interface EncryptAlgorithm : Algorithm
internal sealed external interface DecryptAlgorithm : Algorithm
internal sealed external interface CipherAlgorithm : EncryptAlgorithm, DecryptAlgorithm
internal sealed external interface RsaOaepParams : CipherAlgorithm {
    var label: ByteArray?
}

internal fun RsaOaepParams(label: ByteArray?): RsaOaepParams = Algorithm("RSA-OAEP") {
    this.label = label
}

internal external interface AesCtrParams : CipherAlgorithm {
    var counter: ByteArray
    var length: Int
}

internal external interface AesCbcParams : CipherAlgorithm {
    var iv: ByteArray
}

internal external interface AesGcmParams : CipherAlgorithm {
    var additionalData: ByteArray?
    var iv: ByteArray
    var tagLength: Int
}

internal inline fun AesCtrParams(block: AesCtrParams.() -> Unit): AesCtrParams = CipherAlgorithm("AES-CTR", block)
internal inline fun AesCbcParams(block: AesCbcParams.() -> Unit): AesCbcParams = CipherAlgorithm("AES-CBC", block)
internal inline fun AesGcmParams(block: AesGcmParams.() -> Unit): AesGcmParams = CipherAlgorithm("AES-GCM", block)

private inline fun <T : CipherAlgorithm> CipherAlgorithm(name: String, block: T.() -> Unit): T =
    js("{}").unsafeCast<T>().apply {
        this.name = name
        block()
    }
