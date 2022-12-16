package dev.whyoleg.cryptography.algorithms.aes

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.key.*

public object AES {
    public object GCM : KeyAlgorithm<GCM.Key, SymmetricKeyParameters> {
        public class Box(
            public val nonce: Buffer,
            public val ciphertext: Buffer,
            public val tag: Buffer,
        )

        //sync and async
        public fun importKey(format: SymmetricKeyFormat, data: Buffer): Key = TODO()

        //sync and async
        public fun generateKey(size: SymmetricKeySize): Key = TODO()

        public class CipherParameters(
            public val tagLength: BinarySize = 128.bits,
        ) : CryptographyParameters<CipherParameters, CipherParameters.Builder> {
            override fun copy(block: Builder.() -> Unit): CipherParameters {
                return Builder(tagLength).apply(block).build()
            }

            public class Builder internal constructor(
                public var tagLength: BinarySize,
            ) {
                internal fun build(): CipherParameters = CipherParameters(tagLength)
            }
        }

        public interface Key : Cipher.Provider<CipherParameters> {
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
