package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.api.*

public interface AesKey : CryptographyPrimitive

public sealed class AesGcmCipherParameters(
    public val padding: Boolean,
    public val tagSize: Int,
)

public class AesGcmEncryptParameters(
    padding: Boolean = true,
    tagSize: Int = 16,
    public val iv: ByteArray? = null,
) : AesGcmCipherParameters(padding, tagSize)

public class AesGcmDecryptParameters(
    padding: Boolean = true,
    tagSize: Int = 16,
) : AesGcmCipherParameters(padding, tagSize)

public class AesGcmEnvelopeEncryptRequest(
    public val key: AesKey,

    public val plaintext: ByteArray,
    public val associatedData: ByteArray?,

    public val parameters: AesGcmEncryptParameters,
) // -> CiphertextEnvelope

public class AesGcmBoxEncryptRequest(
    public val key: AesKey,

    public val plaintext: ByteArray,
    public val associatedData: ByteArray?,

    public val parameters: AesGcmEncryptParameters,
) // -> AesGcmBox

public class AesGcmEnvelopeDecryptRequest(
    public val key: AesKey,

    public val ciphertext: CiphertextEnvelope,
    public val associatedData: ByteArray?,

    public val parameters: AesGcmDecryptParameters,
) // -> ByteArray

public class AesGcmBoxDecryptRequest(
    public val key: AesKey,

    public val ciphertext: AesGcmBox,
    public val associatedData: ByteArray?,

    public val parameters: AesGcmDecryptParameters,
) // -> ByteArray

public class AesGcmBox(
    public val iv: ByteArray,
    public val ciphertext: ByteArray,
    public val authTag: ByteArray,
)

public class CiphertextEnvelope(
    public val ciphertext: ByteArray,
)
