package dev.whyoleg.cryptography.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.apple.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.random.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*

internal class CCHmac(
    private val state: AppleState,
) : HMAC {
    override fun keyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<HMAC.Key.Format, HMAC.Key> {
        val (hmacAlgorithm, keySize) = when (digest) {
            SHA1   -> kCCHmacAlgSHA1 to CC_SHA1_DIGEST_LENGTH
            SHA256 -> kCCHmacAlgSHA256 to CC_SHA256_DIGEST_LENGTH
            SHA384 -> kCCHmacAlgSHA384 to CC_SHA384_DIGEST_LENGTH
            SHA512 -> kCCHmacAlgSHA512 to CC_SHA512_DIGEST_LENGTH
            else   -> throw CryptographyException("Unsupported hash algorithm: $digest")
        }
        return HmacKeyDecoder(state, hmacAlgorithm)
    }

    override fun keyGenerator(digest: CryptographyAlgorithmId<Digest>): KeyGenerator<HMAC.Key> {
        val (hmacAlgorithm, keySize) = when (digest) {
            SHA1   -> kCCHmacAlgSHA1 to CC_SHA1_DIGEST_LENGTH
            SHA256 -> kCCHmacAlgSHA256 to CC_SHA256_DIGEST_LENGTH
            SHA384 -> kCCHmacAlgSHA384 to CC_SHA384_DIGEST_LENGTH
            SHA512 -> kCCHmacAlgSHA512 to CC_SHA512_DIGEST_LENGTH
            else   -> throw CryptographyException("Unsupported hash algorithm: $digest")
        }
        println(keySize)
        return HmacKeyGenerator(state, keySize, hmacAlgorithm)
    }
}

private class HmacKeyDecoder(
    private val state: AppleState,
    private val hmacAlgorithm: CCHmacAlgorithm,
) : KeyDecoder<HMAC.Key.Format, HMAC.Key> {
    override fun decodeFromBlocking(format: HMAC.Key.Format, input: Buffer): HMAC.Key {
        if (format == HMAC.Key.Format.RAW) return wrapKey(state, input, hmacAlgorithm)
        TODO("$format is not yet supported")
    }

    override suspend fun decodeFrom(format: HMAC.Key.Format, input: Buffer): HMAC.Key {
        return state.execute { decodeFromBlocking(format, input) }
    }
}

private class HmacKeyGenerator(
    private val state: AppleState,
    private val keySizeBytes: Int,
    private val hmacAlgorithm: CCHmacAlgorithm,
) : KeyGenerator<HMAC.Key> {
    override fun generateKeyBlocking(): HMAC.Key {
        val key = CryptographyRandom.nextBytes(keySizeBytes)
        return wrapKey(state, key, hmacAlgorithm)
    }

    override suspend fun generateKey(): HMAC.Key {
        return state.execute { generateKeyBlocking() }
    }
}

private fun wrapKey(
    state: AppleState,
    key: Buffer,
    hmacAlgorithm: CCHmacAlgorithm,
): HMAC.Key = object : HMAC.Key {
    private val signature = HmacSignature(state, key, hmacAlgorithm)
    override fun signatureGenerator(): SignatureGenerator = signature
    override fun signatureVerifier(): SignatureVerifier = signature

    override fun encodeToBlocking(format: HMAC.Key.Format): Buffer {
        if (format == HMAC.Key.Format.RAW) return key
        TODO("$format is not yet supported")
    }

    override suspend fun encodeTo(format: HMAC.Key.Format): Buffer {
        return state.execute { encodeToBlocking(format) }
    }
}

private class HmacSignature(
    private val state: AppleState,
    private val key: Buffer,
    private val hmacAlgorithm: CCHmacAlgorithm,
) : SignatureGenerator, SignatureVerifier {
    override fun generateSignatureBlocking(dataInput: Buffer): Buffer {
        val macOutput = ByteArray(key.size) //TODO: size!!!
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

    override fun verifySignatureBlocking(dataInput: Buffer, signatureInput: Buffer): Boolean {
        return generateSignatureBlocking(dataInput).contentEquals(signatureInput)
    }

    override suspend fun generateSignature(dataInput: Buffer): Buffer {
        return state.execute { generateSignatureBlocking(dataInput) }
    }

    override suspend fun verifySignature(dataInput: Buffer, signatureInput: Buffer): Boolean {
        return state.execute { verifySignatureBlocking(dataInput, signatureInput) }
    }
}
