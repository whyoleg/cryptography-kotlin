package dev.whyoleg.cryptography.webcrypto.external

internal sealed external interface EncryptAlgorithm : Algorithm
internal sealed external interface DecryptAlgorithm : Algorithm
internal sealed external interface CipherAlgorithm : EncryptAlgorithm, DecryptAlgorithm
internal sealed external interface RsaOaepParams : CipherAlgorithm {
    var label: ByteArray?
}

internal fun RsaOaepParams(label: ByteArray?): RsaOaepParams = Algorithm("RSA-OAEP") {
    this.label = label ?: undefined
}

internal external interface AesGcmParams : CipherAlgorithm {
    var additionalData: ByteArray?
    var iv: ByteArray
    var tagLength: Int
}

internal fun AesGcmParams(
    additionalData: ByteArray?,
    iv: ByteArray,
    tagLength: Int,
): AesGcmParams = Algorithm("AES-GCM") {
    this.additionalData = additionalData
    this.iv = iv
    this.tagLength = tagLength
}

internal external interface AesCbcParams : CipherAlgorithm {
    var iv: ByteArray
}

internal fun AesCbcParams(iv: ByteArray): AesCbcParams = Algorithm("AES-CBC") {
    this.iv = iv
}
