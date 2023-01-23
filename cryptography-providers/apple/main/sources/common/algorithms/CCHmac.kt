package dev.whyoleg.cryptography.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.random.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*

internal object CCHmac : HMAC {
    override fun keyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<HMAC.Key.Format, HMAC.Key> {
        val (hmacAlgorithm, keySize) = when (digest) {
            SHA1   -> kCCHmacAlgSHA1 to CC_SHA1_DIGEST_LENGTH
            SHA256 -> kCCHmacAlgSHA256 to CC_SHA256_DIGEST_LENGTH
            SHA384 -> kCCHmacAlgSHA384 to CC_SHA384_DIGEST_LENGTH
            SHA512 -> kCCHmacAlgSHA512 to CC_SHA512_DIGEST_LENGTH
            else   -> throw CryptographyException("Unsupported hash algorithm: $digest")
        }
        return HmacKeyDecoder(hmacAlgorithm)
    }

    override fun keyGenerator(digest: CryptographyAlgorithmId<Digest>): KeyGenerator<HMAC.Key> {
        val (hmacAlgorithm, keySize) = when (digest) {
            SHA1   -> kCCHmacAlgSHA1 to CC_SHA1_DIGEST_LENGTH
            SHA256 -> kCCHmacAlgSHA256 to CC_SHA256_DIGEST_LENGTH
            SHA384 -> kCCHmacAlgSHA384 to CC_SHA384_DIGEST_LENGTH
            SHA512 -> kCCHmacAlgSHA512 to CC_SHA512_DIGEST_LENGTH
            else   -> throw CryptographyException("Unsupported hash algorithm: $digest")
        }
        return HmacKeyGenerator(keySize, hmacAlgorithm)
    }
}

private class HmacKeyDecoder(
    private val hmacAlgorithm: CCHmacAlgorithm,
) : KeyDecoder<HMAC.Key.Format, HMAC.Key> {
    override fun decodeFromBlocking(format: HMAC.Key.Format, input: Buffer): HMAC.Key {
        if (format == HMAC.Key.Format.RAW) return wrapKey(input, hmacAlgorithm)
        TODO("$format is not yet supported")
    }
}

private class HmacKeyGenerator(
    private val keySizeBytes: Int,
    private val hmacAlgorithm: CCHmacAlgorithm,
) : KeyGenerator<HMAC.Key> {
    override fun generateKeyBlocking(): HMAC.Key {
        val key = CryptographyRandom.nextBytes(keySizeBytes)
        return wrapKey(key, hmacAlgorithm)
    }
}

private fun wrapKey(
    key: Buffer,
    hmacAlgorithm: CCHmacAlgorithm,
): HMAC.Key = object : HMAC.Key {
    private val signature = HmacSignature(key, hmacAlgorithm)
    override fun signatureGenerator(): SignatureGenerator = signature
    override fun signatureVerifier(): SignatureVerifier = signature

    override fun encodeToBlocking(format: HMAC.Key.Format): Buffer {
        if (format == HMAC.Key.Format.RAW) return key
        TODO("$format is not yet supported")
    }
}

private class HmacSignature(
    private val key: Buffer,
    private val hmacAlgorithm: CCHmacAlgorithm,
) : SignatureGenerator, SignatureVerifier {
    override fun generateSignatureBlocking(dataInput: Buffer): Buffer {
        val macOutput = ByteArray(key.size)
        val result = CCHmac(
            algorithm = hmacAlgorithm,
            key = key.refTo(0),
            keyLength = key.size.convert(),
            data = dataInput.fixEmpty().refTo(0),
            dataLength = dataInput.size.convert(),
            macOut = macOutput.refTo(0)
        )
        return macOutput
    }

    override fun verifySignatureBlocking(dataInput: Buffer, signatureInput: Buffer): Boolean {
        return generateSignatureBlocking(dataInput).contentEquals(signatureInput)
    }
}
