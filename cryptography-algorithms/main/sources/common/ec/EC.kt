package dev.whyoleg.cryptography.algorithms.ec

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.sha.*
import dev.whyoleg.cryptography.hash.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.signature.*

public object EC {
    public abstract class P521 : KeyGeneratorProvider<P521.KeyPair, CryptographyParameters.Empty> {
        override val defaultKeyGeneratorParameters: CryptographyParameters.Empty get() = CryptographyParameters.Empty

        public companion object : CryptographyAlgorithm<P521>

        public interface KeyPair {
            public val publicKey: PublicKey
            public val privateKey: PrivateKey
        }

        public abstract class PublicKey : VerifierProvider<SignatureParameters<*, *>> {
            override val defaultVerifyParameters: SignatureParameters<*, *> get() = SignatureParameters.Default
        }

        public abstract class PrivateKey : SignerProvider<SignatureParameters<*, *>> {
            final override val defaultSignParameters: SignatureParameters<*, *> get() = SignatureParameters.Default

            public abstract val publicKey: PublicKey //TODO: is it needed?
        }

        //TODO: drop generics and enforce it's contract via custom constructor?
        public class SignatureParameters<T : HashProvider<HP>, HP : CryptographyParameters>(
            public val algorithm: CryptographyAlgorithm<T>,
            public val parameters: HP,
        ) : CryptographyParameters {
            public companion object {
                public val Default: SignatureParameters<*, *> = SignatureParameters(SHA512, CryptographyParameters.Empty)
            }
        }
    }
}
