package dev.whyoleg.cryptography.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.jdk.materials.*
import dev.whyoleg.cryptography.materials.key.*
import java.security.interfaces.*
import java.security.spec.*

internal sealed class JdkEc<PublicK : EC.PublicKey, PrivateK : EC.PrivateKey, KP : EC.KeyPair<PublicK, PrivateK>>(
    protected val state: JdkCryptographyState,
) : EC<PublicK, PrivateK, KP> {
    private val algorithmParameters = state.algorithmParameters("EC")

    private fun curveName(params: AlgorithmParameterSpec): String = algorithmParameters.use {
        it.init(params)
        it.getParameterSpec(ECGenParameterSpec::class.java).name
    }

    protected abstract fun JPublicKey.convert(): PublicK
    protected abstract fun JPrivateKey.convert(): PrivateK
    protected abstract fun JKeyPair.convert(): KP

    final override fun publicKeyDecoder(curve: EC.Curve?): KeyDecoder<EC.PublicKey.Format, PublicK> {
        return EcPublicKeyDecoder(curve?.let { curveName(ECGenParameterSpec(it.jdkName)) })
    }

    final override fun privateKeyDecoder(curve: EC.Curve?): KeyDecoder<EC.PrivateKey.Format, PrivateK> {
        return EcPrivateKeyDecoder(curve?.let { curveName(ECGenParameterSpec(it.jdkName)) })
    }

    final override fun keyPairGenerator(curve: EC.Curve): KeyGenerator<KP> {
        return EcKeyPairGenerator(ECGenParameterSpec(curve.jdkName))
    }

    private val EC.Curve.jdkName: String
        get() = when (this) {
            EC.Curve.P256 -> "secp256r1"
            EC.Curve.P384 -> "secp384r1"
            EC.Curve.P521 -> "secp521r1"
            else          -> name
        }

    private inner class EcKeyPairGenerator(
        private val keyGenParameters: ECGenParameterSpec,
    ) : JdkKeyPairGenerator<KP>(state, "EC") {
        override fun JKeyPairGenerator.init() {
            initialize(keyGenParameters, state.secureRandom)
        }

        override fun JKeyPair.convert(): KP = with(this@JdkEc) { convert() }
    }

    private inner class EcPublicKeyDecoder(
        private val curveName: String?,
    ) : JdkPublicKeyDecoder<EC.PublicKey.Format, PublicK>(state, "EC") {
        override fun JPublicKey.convert(): PublicK {
            check(this is ECPublicKey)
            curveName?.let {
                val keyCurve = curveName(params)
                check(it == keyCurve) { "Key curve $keyCurve is not equal to expected curve $curveName" }
            }

            return with(this@JdkEc) { convert() }
        }
    }

    private inner class EcPrivateKeyDecoder(
        private val curveName: String?,
    ) : JdkPrivateKeyDecoder<EC.PrivateKey.Format, PrivateK>(state, "EC") {
        override fun JPrivateKey.convert(): PrivateK {
            check(this is ECPrivateKey)
            curveName?.let {
                val keyCurve = curveName(params)
                check(it == keyCurve) { "Key curve $keyCurve is not equal to expected curve $curveName" }
            }

            return with(this@JdkEc) { convert() }
        }
    }
}
