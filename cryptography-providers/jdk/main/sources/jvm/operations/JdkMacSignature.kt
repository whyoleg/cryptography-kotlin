package dev.whyoleg.cryptography.jdk.operations


import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.operations.signature.*

internal class JdkMacSignature(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
    algorithm: String,
) : SignatureGenerator, SignatureVerifier {
    private val mac = state.mac(algorithm)

    override fun generateSignatureBlocking(dataInput: ByteArray): ByteArray = mac.use { mac ->
        mac.init(key)
        mac.doFinal(dataInput)
    }

    override fun verifySignatureBlocking(dataInput: ByteArray, signatureInput: ByteArray): Boolean {
        return generateSignatureBlocking(dataInput).contentEquals(signatureInput)
    }
}
