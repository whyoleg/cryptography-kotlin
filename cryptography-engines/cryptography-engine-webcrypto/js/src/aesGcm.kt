package dev.whyoleg.cryptography.engine.webcrypto

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.alg.*
import dev.whyoleg.cryptography.engine.webcrypto.external.*
import dev.whyoleg.vio.*
import org.khronos.webgl.*
import kotlin.coroutines.*
import kotlin.random.*

private val ivSize = 96.bits

public class AesGcmCipherImpl internal constructor(
    private val key: CryptoKey, //TODO
    private val padding: Boolean = false, //TODO
    private val authTagSize: BinarySize = 16.bytes, //TODO
) : AsyncAeadCipher, AsyncBoxedAeadCipher<AesGcmBox> {

    override fun ciphertextSize(plaintextSize: BinarySize): BinarySize {
        return ivSize + plaintextSize + authTagSize
    }

    override fun ciphertextBoxedSize(plaintextSize: BinarySize): BinarySize {
        return plaintextSize
    }

    override fun plaintextSize(ciphertextSize: BinarySize): BinarySize {
        return ciphertextSize - ivSize - authTagSize
    }

    override fun plaintextBoxedSize(ciphertextSize: BinarySize): BinarySize {
        return ciphertextSize
    }

    override suspend fun encryptAsync(
        associatedData: AssociatedData,
        plaintextInput: Plaintext
    ): Ciphertext {
        TODO()
    }

    override suspend fun encryptAsync(
        associatedData: AssociatedData,
        plaintextInput: Plaintext,
        ciphertextOutput: Ciphertext
    ): Ciphertext {
        val iv = Random.nextBytes(ivSize.bytes)

        return suspendCoroutine<Ciphertext> { cont ->
            WebCrypto.subtle.encrypt(
                AesGcmParams {
                    additionalData = associatedData.value
                    this.iv = iv
                    tagLength = tagSize * 8
                },
                key,
                plaintextInput.value
            )
                .then {
                    ciphertextOutput.value
                    cont.resume(Ciphertext(DataView(it).view()))
                }
                .catch { cont.resumeWithException(it) }
        }
    }

    override suspend fun encryptBoxedAsync(
        associatedData: AssociatedData,
        plaintextInput: Plaintext
    ): AesGcmBox {
        TODO()
    }

    override suspend fun encryptBoxedAsync(
        associatedData: AssociatedData,
        plaintextInput: Plaintext,
        ciphertextOutput: AesGcmBox
    ): AesGcmBox {
        TODO()
    }

    override suspend fun decryptAsync(
        associatedData: AssociatedData,
        ciphertextInput: Ciphertext
    ): Plaintext {
        TODO()
    }

    override suspend fun decryptAsync(
        associatedData: AssociatedData,
        ciphertextInput: Ciphertext,
        plaintextOutput: Plaintext
    ): Plaintext {
        TODO()
    }

    override suspend fun decryptBoxedAsync(
        associatedData: AssociatedData,
        ciphertextInput: AesGcmBox
    ): Plaintext {
        TODO()
    }

    override suspend fun decryptBoxedAsync(
        associatedData: AssociatedData,
        ciphertextInput: AesGcmBox,
        plaintextOutput: Plaintext
    ): Plaintext {
        TODO()
    }

}