package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.KeyGenerator
import dev.whyoleg.cryptography.providers.jdk.*
import javax.crypto.*
import javax.crypto.spec.*

internal class JdkCmac(
    private val state: JdkCryptographyState,
    val algorithm: String = "AESCMAC",
) : CMAC {

    override fun keyGenerator(
        cipherParameters: ByteArray,
        algorithm: String,
    ): KeyGenerator<CMAC.Key> {
        return CmacKeyGenerator(cipherParameters, algorithm)
    }

    private class CmacKeyGenerator(
        private val cipherParameters: ByteArray,
        private val algorithm: String,
    ) : KeyGenerator<CMAC.Key> {

        override fun generateKeyBlocking(): CMAC.Key {
            val keySpec = SecretKeySpec(cipherParameters, algorithm)
            return CmacKey(keySpec, cipherParameters)
        }
    }

    private class CmacKey(private val keySpec: SecretKeySpec, private val key: ByteArray) : CMAC.Key {
        private val mac: Mac = Mac.getInstance(keySpec.algorithm).apply {
            init(keySpec)
        }

        override fun update(data: ByteArray) {
            mac.update(data)
        }

        override fun update(data: ByteArray, startIndex: Int, endIndex: Int) {
            mac.update(data, startIndex, endIndex)
        }

        override fun reset() {
            mac.reset()
        }

        override fun encodeToByteArrayBlocking(format: CMAC.Key.Format): ByteArray = when (format) {
            CMAC.Key.Format.RAW -> {
                val result = byteArrayOf()
                mac.doFinal(result, 0)
                result
            }
        }
    }
}