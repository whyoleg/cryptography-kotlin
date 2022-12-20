package dev.whyoleg.cryptography.jdk

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.signature.*
import javax.crypto.*

internal class JdkMacSignatureProvider(
    private val state: JdkCryptographyState,
    private val key: SecretKey,
    private val algorithm: String,
) : SignatureProvider<CryptographyParameters.Empty>(ENGINE_ID) {
    override fun provideOperation(parameters: CryptographyParameters.Empty): Signature = JdkMacSignature(state, key, algorithm)
}

internal class JdkMacSignature(
    private val state: JdkCryptographyState,
    private val key: SecretKey,
    algorithm: String,
) : Signature {
    private val mac = threadLocal { state.provider.mac(algorithm) }

    override val signatureSize: Int get() = mac.get().macLength

    override fun signBlocking(dataInput: Buffer): Buffer {
        val mac = mac.get()
        mac.init(key)
        return mac.doFinal(dataInput)
    }

    override fun signBlocking(dataInput: Buffer, signatureOutput: Buffer): Buffer {
        val mac = mac.get()
        mac.init(key)
        mac.update(dataInput)
        mac.doFinal(signatureOutput, 0)
        return signatureOutput
    }

    override fun verifyBlocking(dataInput: Buffer, signatureInput: Buffer): Boolean {
        return signBlocking(dataInput).contentEquals(signatureInput)
    }

    override suspend fun sign(dataInput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override suspend fun sign(dataInput: Buffer, signatureOutput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override fun signFunction(): SignFunction {
        TODO("Not yet implemented")
    }

    override suspend fun verify(dataInput: Buffer, signatureInput: Buffer): Boolean {
        TODO("Not yet implemented")
    }

    override fun verifyFunction(): VerifyFunction {
        TODO("Not yet implemented")
    }
}
