package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface CMAC : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<CMAC> get() = Companion

    public companion object : CryptographyAlgorithmId<CMAC>("CMAC")

    public fun init(parameters: ByteArray)
    public fun update(data: ByteArray)
    public fun update(data: ByteArray, startIndex: Int, endIndex: Int)
    public fun doFinal(): ByteArray
    public fun doFinal(out: ByteArray, offset: Int)
    public fun reset()
}