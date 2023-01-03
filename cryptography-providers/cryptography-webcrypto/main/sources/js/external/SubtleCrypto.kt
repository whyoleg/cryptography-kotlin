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
        keyData: ByteArray,
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

internal fun SubtleCrypto.exportKeyBinary(format: String, key: CryptoKey): Promise<ByteArray> = exportKey(format, key).then { keyData ->
    when (format) {
        "jwk" -> JSON.stringify(keyData).encodeToByteArray()
        else  -> keyData.unsafeCast<ArrayBuffer>().toByteArray()
    }
}
