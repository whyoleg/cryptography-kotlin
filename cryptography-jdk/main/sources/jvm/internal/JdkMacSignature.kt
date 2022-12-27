package dev.whyoleg.cryptography.jdk.internal

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.signature.*
import javax.crypto.*

internal class JdkMacSignatureProvider(
    private val state: JdkCryptographyState,
    private val key: SecretKey,
    private val algorithm: String,
) : SignatureProvider<CryptographyOperationParameters.Empty>() {
    override fun provideOperation(parameters: CryptographyOperationParameters.Empty): Signature = JdkMacSignature(state, key, algorithm)
}

internal class JdkMacSignature(
    private val state: JdkCryptographyState,
    private val key: SecretKey,
    algorithm: String,
) : Signature {
    private val mac = threadLocal { state.provider.mac(algorithm) }

    override val signatureSize: Int get() = mac.get().macLength

    override fun generateSignatureBlocking(dataInput: Buffer): Buffer {
        val mac = mac.get()
        mac.init(key)
        return mac.doFinal(dataInput)
    }

    override fun generateSignatureBlocking(dataInput: Buffer, signatureOutput: Buffer): Buffer {
        val mac = mac.get()
        mac.init(key)
        mac.update(dataInput)
        mac.doFinal(signatureOutput, 0)
        return signatureOutput
    }

    override fun signatureGenerationFunction(): SignatureGenerationFunction {
        TODO("Not yet implemented")
    }

    override fun verifySignatureBlocking(dataInput: Buffer, signatureInput: Buffer): Boolean {
        return generateSignatureBlocking(dataInput).contentEquals(signatureInput)
    }

    override fun signatureVerificationFunction(): SignatureVerificationFunction {
        TODO("Not yet implemented")
    }

    override suspend fun generateSignature(dataInput: Buffer): Buffer {
        return state.execute { generateSignatureBlocking(dataInput) }
    }

    override suspend fun generateSignature(dataInput: Buffer, signatureOutput: Buffer): Buffer {
        return state.execute { generateSignatureBlocking(dataInput, signatureOutput) }
    }

    override suspend fun verifySignature(dataInput: Buffer, signatureInput: Buffer): Boolean {
        return state.execute { verifySignatureBlocking(dataInput, signatureInput) }
    }
}
