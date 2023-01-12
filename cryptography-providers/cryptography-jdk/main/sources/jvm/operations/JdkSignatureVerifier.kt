package dev.whyoleg.cryptography.jdk.operations

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.operations.signature.*
import java.security.spec.*

internal class JdkSignatureVerifier(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
    algorithm: String,
    private val parameters: AlgorithmParameterSpec?,
) : SignatureVerifier {
    private val signature = state.signature(algorithm)

    override fun verifySignatureBlocking(dataInput: Buffer, signatureInput: Buffer): Boolean = signature.use { signature ->
        signature.initVerify(key)
        parameters?.let(signature::setParameter)
        signature.update(dataInput)
        signature.verify(signatureInput)
    }

    override suspend fun verifySignature(dataInput: Buffer, signatureInput: Buffer): Boolean {
        return state.execute { verifySignatureBlocking(dataInput, signatureInput) }
    }
}
