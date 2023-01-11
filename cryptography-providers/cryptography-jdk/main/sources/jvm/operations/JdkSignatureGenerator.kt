package dev.whyoleg.cryptography.jdk.operations

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.operations.signature.*
import java.security.spec.*

internal class JdkSignatureGenerator(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
    algorithm: String,
    private val parameters: AlgorithmParameterSpec?,
) : SignatureGenerator {
    private val signature = state.signature(algorithm)

    override val signatureSize: Int get() = TODO()

    override fun generateSignatureBlocking(dataInput: Buffer): Buffer = signature.use { signature ->
        signature.initSign(key, state.secureRandom)
        parameters?.let(signature::setParameter)
        signature.update(dataInput)
        signature.sign()
    }

    override suspend fun generateSignature(dataInput: Buffer): Buffer {
        return state.execute { generateSignatureBlocking(dataInput) }
    }
}
