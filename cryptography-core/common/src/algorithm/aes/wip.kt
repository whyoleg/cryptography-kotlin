package dev.whyoleg.cryptography.algorithm.aes

import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.operation.*
import dev.whyoleg.vio.*


//encryption AES GCM: (CTR - no tag size and auth tag)
// - constructor: provide IV size, Tag size, key
// - init: generated IV
// - update: put data | get data
// - final: generated auth tag

//decryption:
// - constructor: provide IV size, Tag size, Key
// - init: provide IV
// - update: put data | get data
// - final: provide auth tag
//

public class AesGcm(
    public val encrypt: AesGcmEncryptOperation,
    public val decrypt: AesGcmDecryptOperation
) {
    private fun test() {
        encrypt(AssociatedData(BufferView.Empty), Unit).use {
            it.complete()
            println(it.data)
        }
        val result = encrypt.parameterized(AssociatedData(BufferView.Empty), BufferView.Empty)
        val output = decrypt.parameterized(AssociatedData(BufferView.Empty), result)

        encrypt.parameterized(AssociatedData(BufferView.Empty), Unit).use {
            val r = it.complete()
            println(it.data)
        }
        decrypt.parameterized(AssociatedData(BufferView.Empty), InitializationVector(BufferView.Empty)).use {
            val r = it.complete(parameters = AuthTag(BufferView.Empty))
            println(it.data)
        }
    }
}

public class AesGcmBox(
    public val iv: InitializationVector,
    ciphertext: BufferView,
    public val authTag: AuthTag
) : CipherBox(ciphertext)

public interface AesGcmEncryptOperation :
    CipherOperationWithParameterized<AssociatedData, AesGcmParameterizedEncryptOperation>

public interface AesGcmDecryptOperation :
    CipherOperationWithParameterized<AssociatedData, AesGcmParameterizedDecryptOperation>

public interface AesGcmParameterizedEncryptOperation : ParameterizedEncryptOperation<
        AssociatedData, Unit,
        AesGcmBox, AesGcmParameterizedEncryptFunction
        >

public interface AesGcmParameterizedDecryptOperation : ParameterizedDecryptOperation<
        AssociatedData, InitializationVector,
        AesGcmBox, AesGcmParameterizedDecryptFunction
        >

public interface AesGcmParameterizedEncryptFunction :
    ParameterizedCipherFunction<Unit, AuthTag> {
    public val iv: InitializationVector
}

public interface AesGcmParameterizedDecryptFunction :
    ParameterizedCipherFunction<AuthTag, Unit> {
    public val iv: InitializationVector
}

public class InitializationVector(
    public val bufferView: BufferView
)

public class AuthTag(
    public val bufferView: BufferView
)


public interface AesCtrParameterizedCipherFunction :
    ParameterizedCipherFunction<Unit, Unit> {
    public val iv: InitializationVector
}

public class AesCtrBox(
    public val iv: InitializationVector,
    ciphertext: BufferView,
) : CipherBox(ciphertext)

public interface AesCtrParameterizedEncryptOperation : ParameterizedEncryptOperation<
        Unit, Unit,
        AesCtrBox, AesCtrParameterizedCipherFunction
        >

public interface AesCtrParameterizedDecryptOperation : ParameterizedDecryptOperation<
        Unit, InitializationVector,
        AesCtrBox, AesCtrParameterizedCipherFunction
        >

public interface AesCtrEncryptOperation :
    CipherOperationWithParameterized<Unit, AesCtrParameterizedEncryptOperation>

public interface AesCtrDecryptOperation :
    CipherOperationWithParameterized<Unit, AesCtrParameterizedDecryptOperation>

public class AesCtr(
    public val encrypt: AesCtrEncryptOperation,
    public val decrypt: AesCtrDecryptOperation
) {
    private fun test() {
        encrypt(Unit, Unit).use {
            it.complete()
        }
        val result = encrypt.parameterized(Unit, BufferView.Empty)
        val output = decrypt.parameterized(Unit, result)
        encrypt.parameterized(Unit, Unit).use {
            it.iv
            it.complete()
        }
        decrypt.parameterized(
            Unit,
            InitializationVector(BufferView.Empty)
        ).use {
            it.iv
            it.complete()
        }
    }
}