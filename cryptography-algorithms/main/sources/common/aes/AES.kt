package dev.whyoleg.cryptography.algorithms.aes

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.cipher.aead.*
import dev.whyoleg.cryptography.key.*

private suspend fun tests(engine: CryptographyEngine) {

    engine.get(AES.CBC).apply {
        keyDecoder().decodeKeyBlocking("", ByteArray(2))
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

    key.encoder().encodeKeyBlocking("", ByteArray(1))
}

public abstract class AES<K>(
    keyGeneratorProvider: KeyGeneratorProvider<SymmetricKeyParameters, K>,
    keyDecoderProvider: KeyDecoderProvider<CryptographyParameters.Empty, K>,
) : CryptographyAlgorithm {

    public val keyGenerator: KeyGeneratorFactory<SymmetricKeyParameters, K> = keyGeneratorProvider.factory(
        operationId = CryptographyOperationId("AES"),
        defaultParameters = SymmetricKeyParameters.Default,
    )

    public val keyDecoder: KeyDecoderFactory<CryptographyParameters.Empty, K> = keyDecoderProvider.factory(
        operationId = CryptographyOperationId("AES"),
        defaultParameters = CryptographyParameters.Empty,
    )

    public class CBC(
        keyGeneratorProvider: KeyGeneratorProvider<SymmetricKeyParameters, Key>,
        keyDecoderProvider: KeyDecoderProvider<CryptographyParameters.Empty, Key>,
    ) : AES<CBC.Key>(keyGeneratorProvider, keyDecoderProvider) {
        public companion object : CryptographyAlgorithmIdentifier<CBC>

        public class Key(
            cipherProvider: CipherProvider<CipherParameters>,
            keyEncoderProvider: KeyEncoderProvider<CryptographyParameters.Empty>,
        ) {
            public val cipher: CipherFactory<CipherParameters> = cipherProvider.factory(
                operationId = CryptographyOperationId("AES-CBC"),
                defaultParameters = CipherParameters.Default,
            )
            public val encoder: KeyEncoderFactory<CryptographyParameters.Empty> = keyEncoderProvider.factory(
                operationId = CryptographyOperationId("AES"),
                defaultParameters = CryptographyParameters.Empty,
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
    }

    public abstract class GCM(
        keyGeneratorProvider: KeyGeneratorProvider<SymmetricKeyParameters, Key>,
        keyDecoderProvider: KeyDecoderProvider<CryptographyParameters.Empty, Key>,
    ) : AES<GCM.Key>(keyGeneratorProvider, keyDecoderProvider) {
        public companion object : CryptographyAlgorithmIdentifier<GCM>

        public class Key(
            cipherProvider: AeadCipherProvider<CipherParameters>,
            keyEncoderProvider: KeyEncoderProvider<CryptographyParameters.Empty>,
        ) {
            public val cipher: AeadCipherFactory<CipherParameters> = cipherProvider.factory(
                operationId = CryptographyOperationId("AES-GCM"),
                defaultParameters = CipherParameters.Default,
            )
            public val encoder: KeyEncoderFactory<CryptographyParameters.Empty> = keyEncoderProvider.factory(
                operationId = CryptographyOperationId("AES"),
                defaultParameters = CryptographyParameters.Empty,
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

//        public class Box(
//            public val nonce: Buffer,
//            public val ciphertext: Buffer,
//            public val tag: Buffer,
//        )

    }
}
