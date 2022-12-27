package dev.whyoleg.cryptography.webcrypto.external

import org.khronos.webgl.*
import kotlin.js.*

internal external interface SubtleCrypto {
    fun digest(algorithmName: String, data: ByteArray): Promise<ArrayBuffer>
    fun encrypt(algorithm: EncryptAlgorithm, key: CryptoKey, data: ByteArray): Promise<ArrayBuffer>
    fun decrypt(algorithm: DecryptAlgorithm, key: CryptoKey, data: ByteArray): Promise<ArrayBuffer>

    fun importKey(
        format: String, /*"raw" | "pkcs8" | "spki"*/
        keyData: ByteArray,
        algorithm: KeyGenerationAlgorithm,
        extractable: Boolean,
        keyUsages: Array<String>,
    ): Promise<CryptoKey>

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

    fun sign(algorithm: SignAlgorithm, key: CryptoKey, data: ByteArray): Promise<ByteArray>
    fun verify(algorithm: VerifyAlgorithm, key: CryptoKey, signature: ByteArray, data: ByteArray): Promise<Boolean>
}
