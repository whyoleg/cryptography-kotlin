package dev.whyoleg.cryptography.webcrypto.internal

import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.key.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.webcrypto.external.*

internal object HmacKeyGeneratorProvider : KeyGeneratorProvider<HMAC.KeyGeneratorParameters, HMAC.Key>() {
    override fun provideOperation(parameters: HMAC.KeyGeneratorParameters): KeyGenerator<HMAC.Key> = HmacKeyGenerator(
        hashAlgorithm = parameters.digest.hashAlgorithmName()
    )
}

internal class HmacKeyGenerator(
    hashAlgorithm: String,
) : WebCryptoSymmetricKeyGenerator<HMAC.Key>(
    HmacKeyGenerationAlgorithm(hashAlgorithm),
    arrayOf("sign", "verify"),
) {
    override fun wrap(key: CryptoKey): HMAC.Key {
        return HMAC.Key(
            HmacSignature(key),
            NotSupportedProvider()
        )
    }

    private class HmacSignature(key: CryptoKey) : SignatureProvider<CryptographyOperationParameters.Empty>(),
        Signature,
        Signer by WebCryptoSigner(Algorithm("HMAC"), key, 0),
        Verifier by WebCryptoVerifier(Algorithm("HMAC"), key, 0) {
        override val signatureSize: Int
            get() = 0

        override fun provideOperation(parameters: CryptographyOperationParameters.Empty): Signature = this
    }
}
