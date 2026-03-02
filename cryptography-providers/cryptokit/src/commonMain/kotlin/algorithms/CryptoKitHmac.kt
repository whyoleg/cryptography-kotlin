/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swift.DwcCryptoKitInterop.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*
import platform.Foundation.*

@OptIn(UnsafeNumber::class)
internal object CryptoKitHmac : BaseHmac() {
    override fun blockSize(digest: CryptographyAlgorithmId<Digest>): Int = when (digest) {
        MD5    -> CC_MD5_BLOCK_BYTES
        SHA1   -> CC_SHA1_BLOCK_BYTES
        SHA256 -> CC_SHA256_BLOCK_BYTES
        SHA384 -> CC_SHA384_BLOCK_BYTES
        SHA512 -> CC_SHA512_BLOCK_BYTES
        else   -> throw IllegalStateException("Unsupported hash algorithm: $digest")
    }

    override fun wrapKey(digest: CryptographyAlgorithmId<Digest>, rawKey: ByteArray): HMAC.Key = HmacKey(digest, rawKey)

    private class HmacKey(
        digest: CryptographyAlgorithmId<Digest>,
        key: ByteArray,
    ) : BaseKey(digest, key) {
        private val signature = HmacSignature(key.toNSData(), hashAlgorithm(digest), digestSize(digest))
        override fun signatureGenerator(): SignatureGenerator = signature
        override fun signatureVerifier(): SignatureVerifier = signature

        private fun hashAlgorithm(digest: CryptographyAlgorithmId<Digest>): DwcHashAlgorithm = when (digest) {
            MD5    -> DwcHashAlgorithmMd5
            SHA1   -> DwcHashAlgorithmSha1
            SHA256 -> DwcHashAlgorithmSha256
            SHA384 -> DwcHashAlgorithmSha384
            SHA512 -> DwcHashAlgorithmSha512
            else   -> throw IllegalStateException("Unsupported hash algorithm: $digest")
        }

        private fun digestSize(digest: CryptographyAlgorithmId<Digest>): Int = when (digest) {
            MD5    -> CC_MD5_DIGEST_LENGTH
            SHA1   -> CC_SHA1_DIGEST_LENGTH
            SHA256 -> CC_SHA256_DIGEST_LENGTH
            SHA384 -> CC_SHA384_DIGEST_LENGTH
            SHA512 -> CC_SHA512_DIGEST_LENGTH
            else   -> throw IllegalStateException("Unsupported hash algorithm: $digest")
        }
    }
}

@OptIn(UnsafeNumber::class)
private class HmacSignature(
    private val key: NSData,
    private val algorithm: DwcHashAlgorithm,
    private val digestSize: Int,
) : SignatureGenerator, SignatureVerifier {
    private fun createFunction() = HmacFunction(
        key = key,
        algorithm = algorithm,
        digestSize = digestSize
    )

    override fun createSignFunction(): SignFunction = createFunction()
    override fun createVerifyFunction(): VerifyFunction = createFunction()
}

@OptIn(UnsafeNumber::class)
private class HmacFunction(
    private val key: NSData,
    private val algorithm: DwcHashAlgorithm,
    private val digestSize: Int,
) : SignFunction, VerifyFunction {
    private var _function: DwcHmacFunction? = DwcHmacFunction(algorithm, key)
    private val function: DwcHmacFunction
        get() = _function ?: error("Function is closed")

    @OptIn(UnsafeNumber::class)
    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        checkBounds(source.size, startIndex, endIndex)

        source.useNSData(startIndex, endIndex, function::doUpdate)
    }

    override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        checkBounds(destination.size, destinationOffset, destinationOffset + digestSize)

        return function.doFinal().getIntoByteArray(destination, destinationOffset).also {
            reset()
        }
    }

    override fun signToByteArray(): ByteArray {
        return function.doFinal().toByteArray().also {
            reset()
        }
    }

    override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
        checkBounds(signature.size, startIndex, endIndex)
        return signToByteArray().contentEquals(signature.copyOfRange(startIndex, endIndex))
    }

    override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
        check(tryVerify(signature, startIndex, endIndex)) { "Invalid signature" }
    }

    override fun reset() {
        checkNotNull(_function) { "Function is closed" }
        _function = DwcHmacFunction(algorithm, key)
    }

    override fun close() {
        _function = null
    }
}
