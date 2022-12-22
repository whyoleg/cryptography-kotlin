package dev.whyoleg.cryptography.corecrypto.internal

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.key.*
import dev.whyoleg.cryptography.operations.signature.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*

internal class HmacKeyGeneratorProvider(
    private val state: CoreCryptoState,
) : KeyGeneratorProvider<HMAC.KeyGeneratorParameters, HMAC.Key>() {
    override fun provideOperation(parameters: HMAC.KeyGeneratorParameters): KeyGenerator<HMAC.Key> {
        val hashAlgorithm = when (parameters.digest) {
            SHA1   -> kCCHmacAlgSHA1
            SHA512 -> kCCHmacAlgSHA512
            else   -> throw CryptographyException("Unsupported hash algorithm: ${parameters.digest}")
        }
        //TODO: size of key
        return HmacKeyGenerator(state, 512, hashAlgorithm)
    }
}

internal class HmacKeyGenerator(
    private val state: CoreCryptoState,
    private val keySizeBytes: Int,
    private val hmacAlgorithm: CCHmacAlgorithm,
) : KeyGenerator<HMAC.Key> {
    override fun generateKeyBlocking(): HMAC.Key {
        val key = ByteArray(keySizeBytes)
        if (
            CCRandomGenerateBytes(key.refTo(0), keySizeBytes.convert()) != kCCSuccess
        ) throw CryptographyException("CCRandomGenerateBytes failed")
        return HMAC.Key(
            HmacSignatureProvider(state, key, hmacAlgorithm),
            NotSupportedProvider()
        )
    }

    override suspend fun generateKey(): HMAC.Key {
        return state.execute { generateKeyBlocking() }
    }
}

internal class HmacSignatureProvider(
    private val state: CoreCryptoState,
    private val key: Buffer,
    private val hmacAlgorithm: CCHmacAlgorithm,
) : SignatureProvider<CryptographyOperationParameters.Empty>() {
    override fun provideOperation(parameters: CryptographyOperationParameters.Empty): Signature = HmacSignature(state, key, hmacAlgorithm)
}

internal class HmacSignature(
    private val state: CoreCryptoState,
    private val key: Buffer,
    private val hmacAlgorithm: CCHmacAlgorithm,
) : Signature {
    override val signatureSize: Int
        get() = TODO("Not yet implemented")

    override fun signBlocking(dataInput: Buffer): Buffer {
        val macOutput = ByteArray(signatureSize) //TODO: size!!!
        val result = CCHmac(
            algorithm = hmacAlgorithm,
            key = key.refTo(0),
            keyLength = key.size.convert(),
            data = dataInput.refTo(0),
            dataLength = dataInput.size.convert(),
            macOut = macOutput.refTo(0)
        )
        //TODO: check error
        return macOutput
    }

    override fun signBlocking(dataInput: Buffer, signatureOutput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override fun verifyBlocking(dataInput: Buffer, signatureInput: Buffer): Boolean {
        return signBlocking(dataInput).contentEquals(signatureInput)
    }

    override suspend fun sign(dataInput: Buffer): Buffer {
        return state.execute { signBlocking(dataInput) }
    }

    override suspend fun sign(dataInput: Buffer, signatureOutput: Buffer): Buffer {
        return state.execute { signBlocking(dataInput, signatureOutput) }
    }

    override suspend fun verify(dataInput: Buffer, signatureInput: Buffer): Boolean {
        return state.execute { verifyBlocking(dataInput, signatureInput) }
    }

    override fun signFunction(): SignFunction {
        TODO("Not yet implemented")
    }

    override fun verifyFunction(): VerifyFunction {
        TODO("Not yet implemented")
    }
}
