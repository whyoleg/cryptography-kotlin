package dev.whyoleg.cryptography.webcrypto.external

internal sealed external interface KeyAlgorithm : Algorithm
internal sealed external interface KeyGenerationAlgorithm : KeyAlgorithm
internal sealed external interface KeyImportAlgorithm : KeyAlgorithm
internal sealed external interface SymmetricKeyGenerationAlgorithm : KeyGenerationAlgorithm
internal sealed external interface AsymmetricKeyGenerationAlgorithm : KeyGenerationAlgorithm

internal sealed external interface HmacKeyAlgorithm : SymmetricKeyGenerationAlgorithm, KeyImportAlgorithm {
    var hash: String
}

internal fun HmacKeyAlgorithm(hash: String): HmacKeyAlgorithm = Algorithm("HMAC") {
    this.hash = hash
}

internal sealed external interface AesKeyGenerationAlgorithm : SymmetricKeyGenerationAlgorithm {
    var length: Int
}

internal fun AesKeyGenerationAlgorithm(name: String, length: Int): AesKeyGenerationAlgorithm =
    Algorithm(name) {
        this.length = length
    }

internal sealed external interface RsaHashedKeyGenerationAlgorithm : AsymmetricKeyGenerationAlgorithm {
    var modulusLength: Int
    var publicExponent: ByteArray
    var hash: String
}

internal fun RsaHashedKeyGenerationAlgorithm(
    name: String, //RSA-PSS | RSA-OAEP
    modulusLength: Int,
    publicExponent: ByteArray,
    hash: String,
): RsaHashedKeyGenerationAlgorithm = Algorithm(name) {
    this.modulusLength = modulusLength
    this.publicExponent = publicExponent
    this.hash = hash
}

internal sealed external interface RsaHashedKeyImportAlgorithm : KeyImportAlgorithm {
    var hash: String
}

internal fun RsaHashedKeyImportAlgorithm(
    name: String, //RSA-PSS | RSA-OAEP
    hash: String,
): RsaHashedKeyImportAlgorithm = Algorithm(name) {
    this.hash = hash
}

internal sealed external interface EcKeyAlgorithm : AsymmetricKeyGenerationAlgorithm, KeyImportAlgorithm {
    var namedCurve: String
}

internal fun EcKeyAlgorithm(
    name: String, //ECDSA | ECDH
    namedCurve: String, //P-256, P-384, P-521
): EcKeyAlgorithm = Algorithm(name) {
    this.namedCurve = namedCurve
}
