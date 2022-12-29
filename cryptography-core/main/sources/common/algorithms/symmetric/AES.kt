package dev.whyoleg.cryptography.algorithms.symmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.operations.cipher.aead.*
import dev.whyoleg.cryptography.operations.key.*
import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(ProviderApi::class)
public interface AES<K : AES.Key> : CryptographyAlgorithm {
    public val keyImporter: KeyImporter<Key.Format, K> //TODO: may be inherit from it?
    public fun keyGenerator(keySize: SymmetricKeySize): KeyGenerator<K>

    @SubclassOptInRequired(ProviderApi::class)
    public interface Key : ExportableKey<Key.Format> {
        public val size: SymmetricKeySize

        public sealed class Format : KeyFormat {
            public object RAW : Format(), KeyFormat.RAW
            public object JWK : Format(), KeyFormat.JWK
        }
    }

    @SubclassOptInRequired(ProviderApi::class)
    public abstract class CBC : AES<CBC.Key> {
        public companion object : CryptographyAlgorithmId<CBC>()

        @SubclassOptInRequired(ProviderApi::class)
        public abstract class Key : AES.Key {
            public abstract fun cipher(padding: Boolean = true): Cipher
        }
    }

    @SubclassOptInRequired(ProviderApi::class)
    public abstract class GCM : AES<GCM.Key> {
        public companion object : CryptographyAlgorithmId<GCM>()

        @SubclassOptInRequired(ProviderApi::class)
        public abstract class Key : AES.Key {
            public abstract fun cipher(tagSize: BinarySize = 128.bits): AeadCipher
        }
    }
}
