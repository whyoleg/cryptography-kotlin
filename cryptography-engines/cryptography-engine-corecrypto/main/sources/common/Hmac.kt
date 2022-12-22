package dev.whyoleg.cryptography.corecrypto

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.mac.*
import dev.whyoleg.cryptography.algorithms.sha.*
import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.signature.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*

private const val ivSizeBytes = 16 //bytes for GCM

internal object Hmac : HMAC {
    override fun syncKeyGenerator(parameters: HMAC.KeyGeneratorParameters): SyncKeyGenerator<HMAC.Key> {
        val hashAlgorithm = when (parameters.algorithm.algorithm) {
            SHA1   -> kCCHmacAlgSHA1
            SHA512 -> kCCHmacAlgSHA512
            else   -> throw CryptographyException("Unsupported hash algorithm: ${parameters.algorithm.algorithm}")
        }
        //TODO: size of key
        return HmacKeyGenerator(512, hashAlgorithm)
    }

    override fun asyncKeyGenerator(parameters: HMAC.KeyGeneratorParameters): AsyncKeyGenerator<HMAC.Key> {
        TODO("Not yet implemented")
    }
}

internal class HmacKeyGenerator(
    private val keySizeBytes: Int,
    private val hmacAlgorithm: CCHmacAlgorithm,
) : SyncKeyGenerator<HMAC.Key> {
    override fun generateKey(): HMAC.Key {
        val key = ByteArray(keySizeBytes)
        if (
            CCRandomGenerateBytes(key.refTo(0), keySizeBytes.convert()) != kCCSuccess
        ) throw CryptographyException("CCRandomGenerateBytes failed")
        return HmacKey(key, hmacAlgorithm)
    }
}

internal class HmacKey(
    private val key: Buffer,
    private val hmacAlgorithm: CCHmacAlgorithm,
) : HMAC.Key {
    override fun syncSignature(parameters: CryptographyOperationParameters.Empty): SyncSignature = HmacSignature(key, hmacAlgorithm)

    override fun asyncSignature(parameters: CryptographyOperationParameters.Empty): AsyncSignature {
        TODO("Not yet implemented")
    }

    override fun signFunction(parameters: CryptographyOperationParameters.Empty): SignFunction {
        TODO("Not yet implemented")
    }

    override fun verifyFunction(parameters: CryptographyOperationParameters.Empty): VerifyFunction {
        TODO("Not yet implemented")
    }
}

internal class HmacSignature(
    private val key: Buffer,
    private val hmacAlgorithm: CCHmacAlgorithm,
) : SyncSignature {
    override val signatureSize: Int
        get() = TODO("Not yet implemented")

    override fun sign(dataInput: Buffer): Buffer {
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

    override fun sign(dataInput: Buffer, signatureOutput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override fun verify(dataInput: Buffer, signatureInput: Buffer): Boolean {
        return sign(dataInput).contentEquals(signatureInput)
    }
}
