package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*

internal class JdkAesCmac(
    private val state: JdkCryptographyState,
) : AES.CMAC {
    private val algorithm = "AESCMAC"
    private val keyWrapper: (JSecretKey) -> AES.CMAC.Key = { key ->
        object : AES.CMAC.Key, JdkEncodableKey<AES.Key.Format>(key) {
            private val signature = JdkMacSignature(state, key, algorithm)
            override fun signatureGenerator(): SignatureGenerator = signature
            override fun signatureVerifier(): SignatureVerifier = signature

            override fun encodeToByteArrayBlocking(format: AES.Key.Format): ByteArray = when (format) {
                AES.Key.Format.JWK -> error("$format is not supported")
                AES.Key.Format.RAW -> encodeToRaw()
            }
        }
    }

    override fun keyDecoder(): KeyDecoder<AES.Key.Format, AES.CMAC.Key> {
        return JdkSecretKeyDecoder<AES.Key.Format, _>(algorithm, keyWrapper)
    }

    override fun keyGenerator(keySize: BinarySize): KeyGenerator<AES.CMAC.Key> {
        return object : KeyGenerator<AES.CMAC.Key> {
            override fun generateKeyBlocking(): AES.CMAC.Key {
                // Use AES KeyGenerator to generate a key
                val keyGen = javax.crypto.KeyGenerator.getInstance("AES")
                keyGen.init(keySize.inBits, state.secureRandom)
                val secretKey = keyGen.generateKey()
                return keyWrapper.invoke(secretKey)
            }
        }
    }
}