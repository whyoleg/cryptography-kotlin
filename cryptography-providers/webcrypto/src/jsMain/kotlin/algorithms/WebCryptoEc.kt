package dev.whyoleg.cryptography.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.webcrypto.external.*
import dev.whyoleg.cryptography.webcrypto.materials.*

internal sealed class WebCryptoEc<PublicK : EC.PublicKey, PrivateK : EC.PrivateKey, KP : EC.KeyPair<PublicK, PrivateK>>(
    private val algorithmName: String,
) : EC<PublicK, PrivateK, KP> {
    protected val publicKeyFormat: (EC.PublicKey.Format) -> String = {
        when (it) {
            EC.PublicKey.Format.RAW -> "raw"
            EC.PublicKey.Format.DER -> "spki"
            EC.PublicKey.Format.PEM -> "pem-EC-spki"
            EC.PublicKey.Format.JWK -> "jwk"
        }
    }
    protected val privateKeyFormat: (EC.PrivateKey.Format) -> String = {
        when (it) {
            EC.PrivateKey.Format.DER -> "pkcs8"
            EC.PrivateKey.Format.PEM -> "pem-EC-pkcs8"
            EC.PrivateKey.Format.JWK -> "jwk"
        }
    }
    protected abstract val publicKeyUsages: Array<String>
    protected abstract val publicKeyWrapper: (CryptoKey) -> PublicK
    protected abstract val privateKeyUsages: Array<String>
    protected abstract val privateKeyWrapper: (CryptoKey) -> PrivateK
    protected abstract val keyPairUsages: Array<String>
    protected abstract val keyPairWrapper: (CryptoKeyPair) -> KP

    final override fun publicKeyDecoder(curve: EC.Curve): KeyDecoder<EC.PublicKey.Format, PublicK> = WebCryptoKeyDecoder(
        EcKeyAlgorithm(algorithmName, curve.name),
        publicKeyUsages, publicKeyFormat, publicKeyWrapper
    )

    final override fun privateKeyDecoder(curve: EC.Curve): KeyDecoder<EC.PrivateKey.Format, PrivateK> = WebCryptoKeyDecoder(
        EcKeyAlgorithm(algorithmName, curve.name),
        privateKeyUsages, privateKeyFormat, privateKeyWrapper
    )

    final override fun keyPairGenerator(curve: EC.Curve): KeyGenerator<KP> = WebCryptoAsymmetricKeyGenerator(
        algorithm = EcKeyAlgorithm(algorithmName, curve.name),
        keyUsages = keyPairUsages,
        keyPairWrapper = keyPairWrapper
    )
}
