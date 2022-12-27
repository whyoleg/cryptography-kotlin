package dev.whyoleg.cryptography.webcrypto.internal

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.asymmetric.RSA.PSS.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.key.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.webcrypto.external.*

internal object RsaPssKeyGeneratorProvider : KeyGeneratorProvider<RSA.KeyPairGeneratorParameters, KeyPair>() {
    override fun provideOperation(parameters: RSA.KeyPairGeneratorParameters): KeyGenerator<KeyPair> = RsaPssKeyGenerator(
        keySizeBits = parameters.keySize.bits,
        publicExponent = when (val exponent = parameters.publicExponent) {
            RSA.PublicExponent.F4        -> byteArrayOf(0x01, 0x00, 0x01)
            is RSA.PublicExponent.Bytes  -> exponent.value
            is RSA.PublicExponent.Number -> TODO("not yet supported")
            is RSA.PublicExponent.Text   -> TODO("not yet supported")
        },
        hashAlgorithm = parameters.digest.hashAlgorithmName(),
    )
}

internal class RsaPssKeyGenerator(
    keySizeBits: Int,
    publicExponent: ByteArray,
    hashAlgorithm: String,
) : WebCryptoAsymmetricKeyGenerator<KeyPair>(
    RsaHashedKeyGenerationAlgorithm("RSA-PSS", keySizeBits, publicExponent, hashAlgorithm),
    arrayOf("sign", "verify")
) {
    override fun wrap(keyPair: CryptoKeyPair): KeyPair {
        return KeyPair(
            PublicKey(
                NotSupportedProvider(),
                RsaPssVerifierProvider(keyPair.publicKey),
            ),
            PrivateKey(
                NotSupportedProvider(),
                RsaPssSignerProvider(keyPair.privateKey)
            )
        )
    }
}

private class RsaPssVerifierProvider(
    private val key: CryptoKey,
) : SignatureVerifierProvider<SignatureParameters>() {
    override fun provideOperation(parameters: SignatureParameters): SignatureVerifier =
        WebCryptoSignatureVerifier(RsaPssParams(parameters.saltLength.bytes), key, 0)
}

private class RsaPssSignerProvider(
    private val key: CryptoKey,
) : SignatureGeneratorProvider<SignatureParameters>() {
    override fun provideOperation(parameters: SignatureParameters): SignatureGenerator =
        WebCryptoSignatureGenerator(RsaPssParams(parameters.saltLength.bytes), key, 0)
}
