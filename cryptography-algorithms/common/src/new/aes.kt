package dev.whyoleg.cryptography.algorithms.new

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.vio.*

public interface AesKey : CryptographyKey.Symmetric

public interface AesGcmEncryptor : Encryptor.WithContext<AssociatedData> {
    public interface Sync : AesGcmEncryptor, Encryptor.WithContext.Sync<AssociatedData, AesGcmBox>
}

public interface AesGcmDecryptor : Decryptor.WithContext<AssociatedData> {
    public interface Sync : AesGcmDecryptor, Decryptor.WithContext.Sync<AssociatedData, AesGcmBox>
}

public interface AesCtrCipher : Cipher
public interface AesCbcCipher : Cipher
public interface AesGcmCipher :
    Cipher.WithContext<AssociatedData>,
    AesGcmEncryptor,
    AesGcmDecryptor {
    public interface Sync :
        Cipher.WithContext.Sync<AssociatedData, AesGcmBox>,
        AesGcmCipher,
        AesGcmEncryptor.Sync,
        AesGcmDecryptor.Sync
}

public class AesGcmBox(
    public val initializationVector: InitializationVector,
    ciphertext: BufferView,
    public val authTag: AuthTag,
) : CipherBox(ciphertext)

public class AesGcmProviderParameters(
    public val padding: Boolean,
    public val tagSize: BinarySize,
) : CryptographyParameters<AesGcmCipher.Sync, AesKey>

public class AesGcmBuilder internal constructor() {
    internal var padding: Boolean = true
    internal var tagSize: BinarySize = 16.bytes

    public fun padding(padding: Boolean) {
        this.padding = padding
    }

    public fun tagSize(tagSize: BinarySize) {
        this.tagSize = tagSize
    }
}

public val AesGcmCipher2: ProviderParametersFactory<
        AesGcmCipher.Sync, AesKey, AesGcmProviderParameters, AesGcmBuilder> =
    ProviderParametersFactory(
        createBuilder = { AesGcmBuilder() },
        build = { AesGcmProviderParameters(it.padding, it.tagSize) }
    )
