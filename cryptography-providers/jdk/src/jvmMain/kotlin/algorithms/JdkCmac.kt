package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.jdk.*
import javax.crypto.*
import javax.crypto.spec.*

internal class JdkCmac(
    private val state: JdkCryptographyState,
    val algorithm: String = "AESCMAC",
) : CMAC {
    private lateinit var mac: Mac

    override fun init(parameters: ByteArray) {
        val keySpec = SecretKeySpec(parameters, "AES")
        state.mac(algorithm).use { mac ->
            mac.init(keySpec)
            this.mac = mac
        }
    }

    override fun update(data: ByteArray) = mac.update(data)

    override fun update(data: ByteArray, startIndex: Int, endIndex: Int) = mac.update(data, startIndex, endIndex)

    override fun doFinal(): ByteArray = mac.doFinal()

    override fun doFinal(out: ByteArray, offset: Int) = mac.doFinal(out, offset)

    override fun reset() = mac.reset()
}