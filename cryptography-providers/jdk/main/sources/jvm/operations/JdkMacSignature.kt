package dev.whyoleg.cryptography.jdk.operations

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.operations.signature.*

internal class JdkMacSignature(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
    algorithm: String,
) : SignatureGenerator, SignatureVerifier {
    private val mac = state.mac(algorithm)

    override fun generateSignatureBlocking(dataInput: Buffer): Buffer = mac.use { mac ->
        mac.init(key)
        mac.doFinal(dataInput)
    }

    override fun verifySignatureBlocking(dataInput: Buffer, signatureInput: Buffer): Boolean {
        return generateSignatureBlocking(dataInput).contentEquals(signatureInput)
    }
}
