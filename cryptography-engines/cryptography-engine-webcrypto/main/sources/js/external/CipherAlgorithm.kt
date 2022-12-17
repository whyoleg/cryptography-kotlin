package dev.whyoleg.cryptography.webcrypto.external

internal external interface CipherAlgorithm {
    var name: String
}

internal external interface AesCtrParams : CipherAlgorithm {
    var counter: ByteArray
    var length: Int
}

internal external interface RsaOaepParams : CipherAlgorithm {
    var label: ByteArray //TODO: type
}

internal external interface AesGcmParams : CipherAlgorithm {
    var additionalData: ByteArray?
    var iv: ByteArray
    var tagLength: Int
}

internal inline fun AesCtrParams(block: AesCtrParams.() -> Unit): AesCtrParams = CipherAlgorithm("AES-CTR", block)
internal inline fun AesGcmParams(block: AesGcmParams.() -> Unit): AesGcmParams = CipherAlgorithm("AES-GCM", block)
internal inline fun RsaOaepParams(block: RsaOaepParams.() -> Unit): RsaOaepParams = CipherAlgorithm("RSA-OAEP", block)

private inline fun <T : CipherAlgorithm> CipherAlgorithm(name: String, block: T.() -> Unit): T =
    js("{}").unsafeCast<T>().apply {
        this.name = name
        block()
    }
