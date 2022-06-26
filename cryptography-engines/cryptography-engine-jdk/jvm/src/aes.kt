package dev.whyoleg.cryptography.engine.jdk

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.alg.*
import dev.whyoleg.vio.*
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.*
import javax.crypto.spec.*
import kotlin.reflect.*

private val ivSize = 96.bits
internal inline fun <T> threadLocal(crossinline block: () -> T): ThreadLocal<T> = object : ThreadLocal<T>() {
    override fun initialValue(): T = block()
}

internal val EmptyByteBuffer = ByteBuffer.allocate(0)

public class AesGcmCipherImpl(
    private val key: SecretKey, //TODO
    private val padding: Boolean = false, //TODO
    private val authTagSize: BinarySize = 128.bits, //TODO
    private val secureRandom: SecureRandom
) :
    SyncAeadCipher, AsyncAeadCipher, StreamAeadCipher,
    SyncBoxedAeadCipher<AesGcmBox>, AsyncBoxedAeadCipher<AesGcmBox> {

    private val cipher: ThreadLocal<Cipher> = threadLocal { Cipher.getInstance("AES/GCM/NoPadding") }

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

    override fun encrypt(
        associatedData: AssociatedData,
        plaintextInput: Plaintext
    ): Ciphertext {
        val ciphertextOutput = Ciphertext(
            ByteBuffer.allocate(ciphertextSize(plaintextInput.value.size.bytes).bytes).view()
        )
        return encrypt(associatedData, plaintextInput, ciphertextOutput)
    }

    override fun encrypt(
        associatedData: AssociatedData,
        plaintextInput: Plaintext,
        ciphertextOutput: Ciphertext
    ): Ciphertext {
        val cipher = cipher.get()
        val iv = ByteArray(ivSize.bytes).also { secureRandom.nextBytes(it) }
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(authTagSize.bits, iv))
        associatedData.value.read { cipher.updateAAD(it) }
        ciphertextOutput.value.write { output ->
            plaintextInput.value.read { input ->
                output.put(iv)
                cipher.doFinal(input, output) //auth tag is appended by default in JDK cipher
            }
        }
        return ciphertextOutput
    }

    override fun encryptBoxed(
        associatedData: AssociatedData,
        plaintextInput: Plaintext
    ): AesGcmBox {
        TODO("Not yet implemented")
    }

    override fun encryptBoxed(
        associatedData: AssociatedData,
        plaintextInput: Plaintext,
        ciphertextOutput: AesGcmBox
    ): AesGcmBox {
        val cipher = cipher.get()
        val iv = ByteArray(ivSize.bytes).also { secureRandom.nextBytes(it) }
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(authTagSize.bits, iv))
        associatedData.value.read { cipher.updateAAD(it) }
        ciphertextOutput.initializationVector.value.write { it.put(iv) }
        ciphertextOutput.ciphertext.value.write { output ->
            plaintextInput.value.read { input ->
                cipher.update(input, output)
            }
        }
        ciphertextOutput.authTag.value.write {
            cipher.doFinal(EmptyByteBuffer, it) //no ciphertext - only auth tag should be in output
        }
        return ciphertextOutput
    }

    override fun decrypt(
        associatedData: AssociatedData,
        ciphertextInput: Ciphertext
    ): Plaintext {
        val plaintextOutput = Plaintext(
            ByteBuffer.allocate(plaintextSize(ciphertextInput.value.size.bytes).bytes).view()
        )
        return decrypt(associatedData, ciphertextInput, plaintextOutput)
    }

    override fun decrypt(
        associatedData: AssociatedData,
        ciphertextInput: Ciphertext,
        plaintextOutput: Plaintext
    ): Plaintext {
        val cipher = cipher.get()
        ciphertextInput.value.read { input ->
            val iv = ByteArray(ivSize.bytes).also { input.get(it) }
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(authTagSize.bits, iv))
            associatedData.value.read { cipher.updateAAD(it) }
            plaintextOutput.value.write { output ->
                cipher.doFinal(input, output) //auth tag is appended by default in JDK cipher
            }
        }
        return plaintextOutput
    }

    override fun decryptBoxed(
        associatedData: AssociatedData,
        ciphertextInput: AesGcmBox
    ): Plaintext {
        TODO("Not yet implemented")
    }

    override fun decryptBoxed(
        associatedData: AssociatedData,
        ciphertextInput: AesGcmBox,
        plaintextOutput: Plaintext
    ): Plaintext {
        val cipher = cipher.get()
        val iv = ciphertextInput.initializationVector.value.read { iv ->
            ByteArray(ivSize.bytes).also { iv.get(it) }
        }
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(authTagSize.bits, iv))
        associatedData.value.read { cipher.updateAAD(it) }
        ciphertextInput.ciphertext.value.read { input ->
            plaintextOutput.value.read { output ->
                cipher.update(input, output)
            }
        }
        ciphertextInput.authTag.value.read {
            cipher.doFinal(it, EmptyByteBuffer) //should produce nothing
        }
        return plaintextOutput
    }

    override fun createEncryptFunction(associatedData: AssociatedData): EncryptFunction {
        TODO("Not yet implemented")
    }

    override fun createDecryptFunction(associatedData: AssociatedData): DecryptFunction {
        TODO("Not yet implemented")
    }

    override suspend fun encryptAsync(
        associatedData: AssociatedData,
        plaintextInput: Plaintext
    ): Ciphertext = encrypt(associatedData, plaintextInput)

    override suspend fun encryptAsync(
        associatedData: AssociatedData,
        plaintextInput: Plaintext,
        ciphertextOutput: Ciphertext
    ): Ciphertext = encrypt(associatedData, plaintextInput, ciphertextOutput)

    override suspend fun encryptBoxedAsync(
        associatedData: AssociatedData,
        plaintextInput: Plaintext
    ): AesGcmBox = encryptBoxed(associatedData, plaintextInput)

    override suspend fun encryptBoxedAsync(
        associatedData: AssociatedData,
        plaintextInput: Plaintext,
        ciphertextOutput: AesGcmBox
    ): AesGcmBox = encryptBoxed(associatedData, plaintextInput, ciphertextOutput)

    override suspend fun decryptAsync(
        associatedData: AssociatedData,
        ciphertextInput: Ciphertext
    ): Plaintext = decrypt(associatedData, ciphertextInput)

    override suspend fun decryptAsync(
        associatedData: AssociatedData,
        ciphertextInput: Ciphertext,
        plaintextOutput: Plaintext
    ): Plaintext = decrypt(associatedData, ciphertextInput, plaintextOutput)

    override suspend fun decryptBoxedAsync(
        associatedData: AssociatedData,
        ciphertextInput: AesGcmBox
    ): Plaintext = decryptBoxed(associatedData, ciphertextInput)

    override suspend fun decryptBoxedAsync(
        associatedData: AssociatedData,
        ciphertextInput: AesGcmBox,
        plaintextOutput: Plaintext
    ): Plaintext = decryptBoxed(associatedData, ciphertextInput, plaintextOutput)

}