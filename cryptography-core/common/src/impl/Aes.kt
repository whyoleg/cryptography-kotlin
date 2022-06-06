package dev.whyoleg.cryptography.impl

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.signature.*
import dev.whyoleg.vio.*

//TODO: defaults for parameters
//TODO: box cipher
public sealed class Aes<K : AesKey> : CryptographyPrimitiveParameters<AesPrimitive<K>> {
    public object CTR : Aes<AesKey>()
    public class CBC(public val padding: Boolean) : Aes<AesCbcKey>()

    public class GCM(
        public val padding: Boolean,
        public val tagSize: BinarySize
    ) : Aes<AesGcmKey>()
}

public interface AesPrimitive<K : AesKey> : CipherPrimitive<K> {
    public val import: KeyImportOperation<Unit, K>
    public val generate: KeyImportOperation<Unit, K>
}

public interface AesKey : CipherSecretKey {
    public val export: KeyExportOperation<Unit, Unit>
}

public interface AesGcmKey : AesKey

public interface AesCbcKey : AesKey

public interface AesGcmBoxEncryptOperation {
    public fun createFunction(): AesGcmBoxEncryptFunction

    public operator fun invoke(input: BufferView): AesGcmBox
    public operator fun invoke(input: BufferView, output: BufferView): AesGcmBox
}

public interface AesGcmBoxDecryptOperation {
    public fun createFunction(initializationVector: InitializationVector): AesGcmBoxDecryptFunction

    public operator fun invoke(box: AesGcmBox): BufferView
    public operator fun invoke(box: AesGcmBox, output: BufferView): BufferView
}

public interface AesGcmBoxEncryptFunction : Closeable {
    public val initializationVector: InitializationVector

    public fun transformOutputSize(inputSize: BinarySize): BinarySize
    public fun transform(input: BufferView): BufferView
    public fun transform(input: BufferView, output: BufferView): BufferView

    public fun completeOutputSize(inputSize: BinarySize): BinarySize
    public fun complete(input: BufferView): AesGcmBox //will contain only last chunk
    public fun complete(input: BufferView, output: BufferView): AesGcmBox //will contain only last chunk
    public fun complete(
        input: BufferView,
        output: BufferView,
        authTagOutput: BufferView
    ): AesGcmBox //will contain only last chunk
}

public class AesGcmBox(
    public val initializationVector: InitializationVector,
    public val data: BufferView,
    public val authTag: AuthTag
)

public interface AesGcmBoxDecryptFunction : Closeable {
    public fun transformOutputSize(inputSize: BinarySize): BinarySize
    public fun transform(input: BufferView): BufferView
    public fun transform(input: BufferView, output: BufferView): BufferView

    public fun completeOutputSize(inputSize: BinarySize): BinarySize
    public fun complete(input: BufferView, authTag: AuthTag): BufferView
    public fun complete(input: BufferView, output: BufferView, authTag: AuthTag): BufferView
}

public class AuthTag(public val value: BufferView)

public class AssociatedData(public val value: BufferView)

public class InitializationVector(public val value: BufferView)