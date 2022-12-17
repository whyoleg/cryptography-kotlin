package dev.whyoleg.cryptography.algorithms.aes

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.key.*

private fun tests(engine: CryptographyEngine) {

    engine.get(AES.GCM).syncKeyGenerator {
        size = SymmetricKeySize.B256
    }.generateKey().syncCipher {
        tagLength = 128.bits
    }.encrypt("Hello, World!".encodeToByteArray())

    val gcm = engine.get(AES.GCM)

    val generator = gcm.syncKeyGenerator {
        size = SymmetricKeySize.B256
    }

    val key = generator.generateKey()

    val exporter = key.syncKeyExporter {

    }

    exporter.exportKey(format.PEM, output)
    exporter.exportKey(format.DER, output)

    val cipher = key.syncCipher {
        tagLength = 128.bits
    }

    cipher.encrypt("Hello, World!".encodeToByteArray())
}

public object AES {
    public abstract class GCM : KeyGeneratorProvider<SymmetricKeyParameters, GCM.Key> {
        public companion object : CryptographyAlgorithm<GCM>

        public class Box(
            public val nonce: Buffer,
            public val ciphertext: Buffer,
            public val tag: Buffer,
        )

        final override val defaultKeyGeneratorParameters: SymmetricKeyParameters get() = SymmetricKeyParameters(SymmetricKeySize.B256)


        //sync and async
        public fun importKey(format: SymmetricKeyFormat, data: Buffer): Key = TODO()

        //sync and async
        public fun generateKey(size: SymmetricKeySize): Key = TODO()

        public class CipherParameters(
            public val tagLength: BinarySize = 128.bits,
        ) : CopyableCryptographyParameters<CipherParameters, CipherParameters.Builder>() {
            override fun builder(): Builder = Builder(tagLength)
            override fun build(builder: Builder): CipherParameters = CipherParameters(builder.tagLength)

            public class Builder internal constructor(
                public var tagLength: BinarySize,
            )
        }

        public interface Key : CipherProvider<CipherParameters> {
            //boxed
            //boxed async
            //encryp/decrypt function

            //expoort sync and async
            public fun export(format: SymmetricKeyFormat): Buffer
            public fun export(format: SymmetricKeyFormat, output: Buffer): Buffer
        }
        //create from key?
    }
}
