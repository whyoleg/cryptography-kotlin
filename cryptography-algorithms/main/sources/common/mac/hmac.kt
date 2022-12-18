package dev.whyoleg.cryptography.algorithms.mac

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.sha.*
import dev.whyoleg.cryptography.hash.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.signature.*

public interface HMAC : KeyGeneratorProvider<HMAC.Key, HMAC.KeyGeneratorParameters> {
    override val defaultKeyGeneratorParameters: KeyGeneratorParameters get() = KeyGeneratorParameters.Default

    public companion object : CryptographyAlgorithm<HMAC>

    public interface Key : SignatureProvider<CryptographyParameters.Empty> {
        override val defaultSignatureParameters: CryptographyParameters.Empty get() = CryptographyParameters.Empty
    }

    public class KeyGeneratorParameters(
        public val algorithm: ParameterizedAlgorithm = ParameterizedAlgorithm(SHA512, CryptographyParameters.Empty),
    ) : CryptographyParameters {
        public companion object {
            public val Default: KeyGeneratorParameters = KeyGeneratorParameters()
        }
    }
}

public class ParameterizedAlgorithm private constructor(
    public val algorithm: CryptographyAlgorithm<*>,
    public val parameters: CryptographyParameters,
) {
    public companion object {
        public operator fun <T : HashProvider<HP>, HP : CryptographyParameters> invoke(
            algorithm: CryptographyAlgorithm<T>,
            parameters: HP,
        ): ParameterizedAlgorithm = ParameterizedAlgorithm(algorithm, parameters)
    }
}
