package dev.whyoleg.cryptography.webcrypto.external

import dev.whyoleg.cryptography.webcrypto.*
import org.khronos.webgl.*
import kotlin.js.Promise

internal external interface SubtleCrypto {
    fun digest(algorithmName: String, data: ByteArray): Promise<ArrayBuffer>

    fun encrypt(algorithm: EncryptAlgorithm, key: CryptoKey, data: ByteArray): Promise<ArrayBuffer>
    fun decrypt(algorithm: DecryptAlgorithm, key: CryptoKey, data: ByteArray): Promise<ArrayBuffer>

    fun sign(algorithm: SignAlgorithm, key: CryptoKey, data: ByteArray): Promise<ArrayBuffer>
    fun verify(algorithm: VerifyAlgorithm, key: CryptoKey, signature: ByteArray, data: ByteArray): Promise<Boolean>

    fun deriveBits(algorithm: DerivationAlgorithm, baseKey: CryptoKey, length: Int): Promise<ArrayBuffer>

    fun importKey(
        format: String, /*"raw" | "pkcs8" | "spki"*/
        keyData: Any, /*JSON if jwk, ArrayBuffer otherwise*/
        algorithm: KeyImportAlgorithm,
        extractable: Boolean,
        keyUsages: Array<String>,
    ): Promise<CryptoKey>

    fun exportKey(
        format: String, /*"raw" | "pkcs8" | "spki"*/
        key: CryptoKey,
    ): Promise<Any /*JSON if jwk, ArrayBuffer otherwise*/>

    fun generateKey(
        algorithm: SymmetricKeyGenerationAlgorithm,
        extractable: Boolean,
        keyUsages: Array<String>,
    ): Promise<CryptoKey>

    fun generateKey(
        algorithm: AsymmetricKeyGenerationAlgorithm,
        extractable: Boolean,
        keyUsages: Array<String>,
    ): Promise<CryptoKeyPair>
}

internal fun SubtleCrypto.exportKeyBinary(format: String, key: CryptoKey): Promise<ByteArray> {
    val fixedFormat = format.substringAfterLast("-")
    return exportKey(fixedFormat, key).then { keyData ->
        when {
            format == "jwk"          -> JSON.stringify(keyData).encodeToByteArray()
            format.startsWith("pem") -> {
                val pemAlgorithm = format.substringAfter("pem-").substringBefore("-")
                val type = when (fixedFormat) {
                    "pkcs8" -> " PRIVATE KEY"
                    "spki"  -> " PUBLIC KEY"
                    else    -> error("Unsupported format: $fixedFormat")
                }
                keyData.unsafeCast<ArrayBuffer>().encodeToPem(pemAlgorithm + type)
            }
            else                     -> keyData.unsafeCast<ArrayBuffer>().toByteArray()
        }
    }
}

internal fun SubtleCrypto.importKeyBinary(
    format: String, /*"raw" | "pkcs8" | "spki"*/
    keyData: ByteArray, /*JSON if jwk, ArrayBuffer otherwise*/
    algorithm: KeyImportAlgorithm,
    extractable: Boolean,
    keyUsages: Array<String>,
): Promise<CryptoKey> {
    val fixedFormat = format.substringAfterLast("-")
    val key = when {
        format == "jwk"          -> JSON.parse<Any>(keyData.decodeToString())
        format.startsWith("pem") -> {
            val pemAlgorithm = format.substringAfter("pem-").substringBefore("-")
            val (type, decoded) = keyData.decodeFromPem()
            val s = when (fixedFormat) {
                "pkcs8" -> "PRIVATE KEY"
                "spki"  -> "PUBLIC KEY"
                else    -> error("Unsupported format: $fixedFormat")
            }
            check(type == s || type == "$pemAlgorithm $s") {
                "Wrong PEM type, expected `$s` or `$pemAlgorithm $s` got `$type`"
            }
            decoded
        }
        else                     -> keyData
    }

    return importKey(fixedFormat, key, algorithm, extractable, keyUsages)
}

private fun ArrayBuffer.encodeToPem(type: String): ByteArray =
    """
    |-----BEGIN $type-----
    |${encodeBase64(this)}
    |-----END $type-----
    """.trimMargin().encodeToByteArray()

private fun ByteArray.decodeFromPem(): Pair<String, ByteArray> {
    val lines = decodeToString().split("\n")
    check(lines.size >= 3) { "Invalid PEM format" }
    val headerType = lines.first().substringAfter("-----BEGIN ").substringBefore("-----").trim()
    val footerType = lines.last().substringAfter("-----END ").substringBefore("-----").trim()

    check(headerType == footerType) { "Invalid PEM format, BEGIN type: `$headerType`, END type: `$footerType`" }
    return headerType to decodeBase64(lines.drop(1).dropLast(1).joinToString("\n"))
}
