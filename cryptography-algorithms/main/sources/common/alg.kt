package dev.whyoleg.cryptography.algorithms

public class AesBox(
    public val iv: ByteArray,
    public val ciphertext: ByteArray,
)

public class AesCbcParameters(
    public val padding: Boolean = true,
)
