package dev.whyoleg.cryptography.algorithms.symmetric.mac

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.provider.*

//TODO: decide on how we can support CMAC/GMAC

@SubclassOptInRequired(ProviderApi::class)
public abstract class HMAC : CryptographyAlgorithm, KeyDecoder<HMAC.Key.Format, HMAC.Key> {
    public companion object : CryptographyAlgorithmId<HMAC>()

    public abstract fun keyGenerator(digest: Digest): KeyGenerator<Key>

    @SubclassOptInRequired(ProviderApi::class)
    public abstract class Key : EncodableKey<Key.Format>, SignatureGenerator, SignatureVerifier {
        public sealed class Format : KeyFormat {
            public object RAW : Format(), KeyFormat.RAW
            public object JWK : Format(), KeyFormat.JWK
        }
    }
}
