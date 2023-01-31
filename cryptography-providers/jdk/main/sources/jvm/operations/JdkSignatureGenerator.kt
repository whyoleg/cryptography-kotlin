package dev.whyoleg.cryptography.jdk.operations


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

    override fun generateSignatureBlocking(dataInput: ByteArray): ByteArray = signature.use { signature ->
        signature.initSign(key, state.secureRandom)
        parameters?.let(signature::setParameter)
        signature.update(dataInput)
        signature.sign()
    }
}
