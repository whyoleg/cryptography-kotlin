package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.key.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface CMAC : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<CMAC> get() = Companion

    public companion object : CryptographyAlgorithmId<CMAC>("CMAC")

    public fun keyGenerator(cipherParameters: ByteArray, algorithm: String = "AESCMAC"): KeyGenerator<Key>

    public interface Key : EncodableKey<Key.Format> {
        public fun update(data: ByteArray)
        public fun update(data: ByteArray, startIndex: Int, endIndex: Int)
        public fun reset()
        public enum class Format : KeyFormat { RAW }
    }
}