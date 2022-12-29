@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.algorithms.symmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.operations.cipher.aead.*
import dev.whyoleg.cryptography.operations.key.*
import dev.whyoleg.cryptography.provider.*

public abstract class AES<K : AES.Key> @ProviderApi constructor(
    keyGeneratorProvider: KeyGeneratorProvider<SymmetricKeyParameters, K>,
    keyDecoderProvider: KeyDecoderProvider<CryptographyOperationParameters.Empty, K, Key.Format>,
) : CryptographyAlgorithm() {

    public val keyGenerator: KeyGeneratorFactory<SymmetricKeyParameters, K> = keyGeneratorProvider.factory(
        operationId = CryptographyOperationId("AES"),
        defaultParameters = SymmetricKeyParameters.Default,
    )

    public val keyDecoder: KeyDecoderFactory<CryptographyOperationParameters.Empty, K, Key.Format> = keyDecoderProvider.factory(
        operationId = CryptographyOperationId("AES"),
        defaultParameters = CryptographyOperationParameters.Empty,
    )

    public abstract class Key @ProviderApi constructor(
        keyEncoderProvider: KeyEncoderProvider<CryptographyOperationParameters.Empty, Format>,
    ) {
        public val encoder: KeyEncoderFactory<CryptographyOperationParameters.Empty, Format> = keyEncoderProvider.factory(
            operationId = CryptographyOperationId("AES"),
            defaultParameters = CryptographyOperationParameters.Empty,
        )

        public sealed class Format : KeyFormat {
            public object RAW : Format(), KeyFormat.RAW
            public object JWK : Format(), KeyFormat.JWK
        }
    }

    public class CBC @ProviderApi constructor(
        keyGeneratorProvider: KeyGeneratorProvider<SymmetricKeyParameters, Key>,
        keyDecoderProvider: KeyDecoderProvider<CryptographyOperationParameters.Empty, Key, AES.Key.Format>,
    ) : AES<CBC.Key>(keyGeneratorProvider, keyDecoderProvider) {
        public companion object : CryptographyAlgorithmIdentifier<CBC>()


        public class Key @ProviderApi constructor(
            cipherProvider: CipherProvider<CipherParameters>,
            keyEncoderProvider: KeyEncoderProvider<CryptographyOperationParameters.Empty, Format>,
        ) : AES.Key(keyEncoderProvider) {
            public val cipher: CipherFactory<CipherParameters> = cipherProvider.factory(
                operationId = CryptographyOperationId("AES-CBC"),
                defaultParameters = CipherParameters.Default,
            )
        }

        public class CipherParameters(
            public val padding: Boolean = true,
        ) : CryptographyOperationParameters.Copyable<CipherParameters, CipherParameters.Builder>() {
            override fun createBuilder(): Builder = Builder(padding)
            override fun buildFrom(builder: Builder): CipherParameters = CipherParameters(builder.padding)

            public class Builder internal constructor(
                public var padding: Boolean,
            )

            public companion object {
                public val Default: CipherParameters = CipherParameters()
            }
        }
    }

    public class GCM @ProviderApi constructor(
        keyGeneratorProvider: KeyGeneratorProvider<SymmetricKeyParameters, Key>,
        keyDecoderProvider: KeyDecoderProvider<CryptographyOperationParameters.Empty, Key, AES.Key.Format>,
    ) : AES<GCM.Key>(keyGeneratorProvider, keyDecoderProvider) {
        public companion object : CryptographyAlgorithmIdentifier<GCM>()

        public class Key @ProviderApi constructor(
            cipherProvider: AeadCipherProvider<CipherParameters>,
            keyEncoderProvider: KeyEncoderProvider<CryptographyOperationParameters.Empty, Format>,
        ) : AES.Key(keyEncoderProvider) {
            public val cipher: AeadCipherFactory<CipherParameters> = cipherProvider.factory(
                operationId = CryptographyOperationId("AES-GCM"),
                defaultParameters = CipherParameters.Default,
            )
        }

        public class CipherParameters(
            public val tagSize: BinarySize = 128.bits,
        ) : CryptographyOperationParameters.Copyable<CipherParameters, CipherParameters.Builder>() {
            override fun createBuilder(): Builder = Builder(tagSize)
            override fun buildFrom(builder: Builder): CipherParameters = CipherParameters(builder.tagSize)

            public class Builder internal constructor(
                public var tagSize: BinarySize,
            )

            public companion object {
                public val Default: CipherParameters = CipherParameters()
            }
        }
    }
}
