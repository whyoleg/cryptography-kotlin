package dev.whyoleg.cryptography.algorithms.symmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.operations.cipher.aead.*
import dev.whyoleg.cryptography.operations.key.*

public abstract class AES<K>(
    keyGeneratorProvider: KeyGeneratorProvider<SymmetricKeyParameters, K>,
    keyDecoderProvider: KeyDecoderProvider<CryptographyParameters.Empty, K, Key.Format>,
) : CryptographyAlgorithm {

    public val keyGenerator: KeyGeneratorFactory<SymmetricKeyParameters, K> = keyGeneratorProvider.factory(
        operationId = CryptographyOperationId("AES"),
        defaultParameters = SymmetricKeyParameters.Default,
    )

    public val keyDecoder: KeyDecoderFactory<CryptographyParameters.Empty, K, Key.Format> = keyDecoderProvider.factory(
        operationId = CryptographyOperationId("AES"),
        defaultParameters = CryptographyParameters.Empty,
    )

    public abstract class Key(
        keyEncoderProvider: KeyEncoderProvider<CryptographyParameters.Empty, Format>,
    ) {
        public val encoder: KeyEncoderFactory<CryptographyParameters.Empty, Format> = keyEncoderProvider.factory(
            operationId = CryptographyOperationId("AES"),
            defaultParameters = CryptographyParameters.Empty,
        )

        public sealed class Format : KeyFormat {
            public object RAW : Format(), KeyFormat.RAW
            public object JWK : Format(), KeyFormat.JWK
        }
    }

    public class CBC(
        keyGeneratorProvider: KeyGeneratorProvider<SymmetricKeyParameters, Key>,
        keyDecoderProvider: KeyDecoderProvider<CryptographyParameters.Empty, Key, AES.Key.Format>,
    ) : AES<CBC.Key>(keyGeneratorProvider, keyDecoderProvider) {
        public companion object : CryptographyAlgorithmIdentifier<CBC>

        public class Key(
            cipherProvider: BoxCipherProvider<CipherParameters, Box>,
            keyEncoderProvider: KeyEncoderProvider<CryptographyParameters.Empty, Format>,
        ) : AES.Key(keyEncoderProvider) {
            public val cipher: BoxCipherFactory<CipherParameters, Box> = cipherProvider.factory(
                operationId = CryptographyOperationId("AES-CBC"),
                defaultParameters = CipherParameters.Default,
            )
        }

        public class CipherParameters(
            public val padding: Boolean = true,
        ) : CopyableCryptographyParameters<CipherParameters, CipherParameters.Builder>() {
            override fun builder(): Builder = Builder(padding)
            override fun build(builder: Builder): CipherParameters = CipherParameters(builder.padding)

            public class Builder internal constructor(
                public var padding: Boolean,
            )

            public companion object {
                public val Default: CipherParameters = CipherParameters()
            }
        }

        public class Box(
            public val nonce: Buffer,
            public val ciphertext: Buffer,
        )
    }

    public class GCM(
        keyGeneratorProvider: KeyGeneratorProvider<SymmetricKeyParameters, Key>,
        keyDecoderProvider: KeyDecoderProvider<CryptographyParameters.Empty, Key, AES.Key.Format>,
    ) : AES<GCM.Key>(keyGeneratorProvider, keyDecoderProvider) {
        public companion object : CryptographyAlgorithmIdentifier<GCM>

        public class Key(
            cipherProvider: AeadBoxCipherProvider<CipherParameters, Box>,
            keyEncoderProvider: KeyEncoderProvider<CryptographyParameters.Empty, Format>,
        ) : AES.Key(keyEncoderProvider) {
            public val cipher: AeadBoxCipherFactory<CipherParameters, Box> = cipherProvider.factory(
                operationId = CryptographyOperationId("AES-GCM"),
                defaultParameters = CipherParameters.Default,
            )
        }

        public class CipherParameters(
            public val tagSize: BinarySize = 128.bits,
        ) : CopyableCryptographyParameters<CipherParameters, CipherParameters.Builder>() {
            override fun builder(): Builder = Builder(tagSize)
            override fun build(builder: Builder): CipherParameters = CipherParameters(builder.tagSize)

            public class Builder internal constructor(
                public var tagSize: BinarySize,
            )

            public companion object {
                public val Default: CipherParameters = CipherParameters()
            }
        }

        public class Box(
            public val nonce: Buffer,
            public val ciphertext: Buffer,
            public val tag: Buffer,
        )
    }
}

private suspend fun tests(engine: CryptographyEngine) {

    engine.get(AES.CBC).apply {
        keyDecoder().decodeKeyBlocking(AES.Key.Format.RAW, ByteArray(2))
            .cipher()
    }.keyGenerator {
        size = SymmetricKeySize.B256
    }.generateKeyBlocking()



    engine.get(AES.GCM).keyGenerator {
        size = SymmetricKeySize.B256
    }.generateKey().cipher {
        tagSize = 128.bits
    }.encrypt("Hello, World!".encodeToByteArray())

    val gcm = engine.get(AES.GCM)

    val generator = gcm.keyGenerator {
        size = SymmetricKeySize.B256
    }

    val key = generator.generateKey()

    val cipher = key.cipher {
        tagSize = 128.bits
    }

    cipher.encrypt("Hello, World!".encodeToByteArray())

    key.encoder().encodeKeyBlocking(AES.Key.Format.JWK, ByteArray(1))
}
