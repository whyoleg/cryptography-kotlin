package dev.whyoleg.cryptography.algorithms.ec

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.sha.*
import dev.whyoleg.cryptography.hash.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.signature.*
import kotlin.jvm.*

//ECDSA and ECDH
public interface EC : KeyGeneratorProvider<EC.KeyPair, EC.KeyGeneratorParameters> {
    override val defaultKeyGeneratorParameters: KeyGeneratorParameters get() = KeyGeneratorParameters.Default

    public companion object : CryptographyAlgorithm<EC>

    public interface KeyPair {
        public val publicKey: PublicKey
        public val privateKey: PrivateKey
    }

    public interface PublicKey : VerifierProvider<SignatureParameters<*, *>> {
        override val defaultVerifyParameters: SignatureParameters<*, *> get() = SignatureParameters.Default
    }

    public interface PrivateKey : SignerProvider<SignatureParameters<*, *>> {
        override val defaultSignParameters: SignatureParameters<*, *> get() = SignatureParameters.Default

        public val publicKey: PublicKey //TODO: is it needed?
    }

    public class KeyGeneratorParameters(
        public val curve: Curve = Curve.P521, //TODO: default curve?
    ) : CryptographyParameters {
        public companion object {
            public val Default: KeyGeneratorParameters = KeyGeneratorParameters()
        }
    }

    //TODO: drop generics and enforce it's contract via custom constructor?
    //ECDSA
    public class SignatureParameters<T : HashProvider<HP>, HP : CryptographyParameters>(
        public val algorithm: CryptographyAlgorithm<T>,
        public val parameters: HP,
    ) : CryptographyParameters {
        public companion object {
            public val Default: SignatureParameters<*, *> = SignatureParameters(SHA512, CryptographyParameters.Empty)
        }
    }


    @JvmInline
    public value class Curve(public val name: String) {
        public companion object {
            public val P521: Curve get() = Curve("P521")
            public val P384: Curve get() = Curve("P384")
            public val P256: Curve get() = Curve("P256")
//        public val Curve25519: ECCurve get() = ECCurve("Curve25519")
        }
    }
}
