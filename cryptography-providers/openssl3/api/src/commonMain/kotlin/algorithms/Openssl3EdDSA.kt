/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import kotlinx.cinterop.*
import platform.posix.*
import kotlin.experimental.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*

internal object Openssl3EdDSA : EdDSA {
    private fun algorithmName(curve: EdDSA.Curve): String = when (curve) {
        EdDSA.Curve.Ed25519 -> "ED25519"
        EdDSA.Curve.Ed448   -> "ED448"
    }
    private fun oid(curve: EdDSA.Curve): ObjectIdentifier = when (curve) {
        EdDSA.Curve.Ed25519 -> EdwardsOids.Ed25519
        EdDSA.Curve.Ed448   -> EdwardsOids.Ed448
    }

    override fun publicKeyDecoder(curve: EdDSA.Curve): KeyDecoder<EdDSA.PublicKey.Format, EdDSA.PublicKey> =
        object : Openssl3PublicKeyDecoder<EdDSA.PublicKey.Format, EdDSA.PublicKey>(algorithmName(curve)) {
            override fun inputType(format: EdDSA.PublicKey.Format): String = when (format) {
                EdDSA.PublicKey.Format.DER -> "DER"
                EdDSA.PublicKey.Format.PEM -> "PEM"
                EdDSA.PublicKey.Format.JWK,
                EdDSA.PublicKey.Format.RAW -> error("should not be called: handled explicitly in decodeFromBlocking")
            }

            override fun decodeFromByteArrayBlocking(format: EdDSA.PublicKey.Format, bytes: ByteArray): EdDSA.PublicKey = when (format) {
                EdDSA.PublicKey.Format.RAW -> super.decodeFromByteArrayBlocking(
                    EdDSA.PublicKey.Format.DER,
                    wrapSubjectPublicKeyInfo(UnknownKeyAlgorithmIdentifier(oid(curve)), bytes)
                )
                else -> super.decodeFromByteArrayBlocking(format, bytes)
            }

            override fun wrapKey(key: CPointer<EVP_PKEY>): EdDSA.PublicKey = EdDsaPublicKey(key, curve)
        }

    override fun privateKeyDecoder(curve: EdDSA.Curve): KeyDecoder<EdDSA.PrivateKey.Format, EdDSA.PrivateKey> =
        object : Openssl3PrivateKeyDecoder<EdDSA.PrivateKey.Format, EdDSA.PrivateKey>(algorithmName(curve)) {
            override fun inputType(format: EdDSA.PrivateKey.Format): String = when (format) {
                EdDSA.PrivateKey.Format.DER -> "DER"
                EdDSA.PrivateKey.Format.PEM -> "PEM"
                EdDSA.PrivateKey.Format.JWK,
                EdDSA.PrivateKey.Format.RAW -> error("should not be called: handled explicitly in decodeFromBlocking")
            }

            override fun decodeFromByteArrayBlocking(format: EdDSA.PrivateKey.Format, bytes: ByteArray): EdDSA.PrivateKey = when (format) {
                EdDSA.PrivateKey.Format.RAW -> super.decodeFromByteArrayBlocking(
                    EdDSA.PrivateKey.Format.DER,
                    wrapPrivateKeyInfo(0, UnknownKeyAlgorithmIdentifier(oid(curve)), bytes)
                )
                else -> super.decodeFromByteArrayBlocking(format, bytes)
            }

            override fun wrapKey(key: CPointer<EVP_PKEY>): EdDSA.PrivateKey = EdDsaPrivateKey(key, curve)
        }

    override fun keyPairGenerator(curve: EdDSA.Curve): KeyGenerator<EdDSA.KeyPair> =
        object : Openssl3KeyPairGenerator<EdDSA.KeyPair>(algorithmName(curve)) {
            override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
            override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): EdDSA.KeyPair = EdDsaKeyPair(
                publicKey = EdDsaPublicKey(keyPair, curve),
                privateKey = EdDsaPrivateKey(keyPair, curve)
            )
        }

    private class EdDsaKeyPair(
        override val publicKey: EdDSA.PublicKey,
        override val privateKey: EdDSA.PrivateKey,
    ) : EdDSA.KeyPair

    private class EdDsaPublicKey(
        key: CPointer<EVP_PKEY>,
        private val curve: EdDSA.Curve,
    ) : EdDSA.PublicKey, Openssl3PublicKeyEncodable<EdDSA.PublicKey.Format>(key) {
        override fun outputType(format: EdDSA.PublicKey.Format): String = when (format) {
            EdDSA.PublicKey.Format.DER -> "DER"
            EdDSA.PublicKey.Format.PEM -> "PEM"
            EdDSA.PublicKey.Format.JWK,
            EdDSA.PublicKey.Format.RAW -> error("should not be called: handled explicitly in encodeToBlocking")
        }

        override fun encodeToByteArrayBlocking(format: EdDSA.PublicKey.Format): ByteArray = when (format) {
            EdDSA.PublicKey.Format.RAW -> unwrapSubjectPublicKeyInfo(
                oid(curve),
                super.encodeToByteArrayBlocking(EdDSA.PublicKey.Format.DER)
            )
            else -> super.encodeToByteArrayBlocking(format)
        }

        override fun signatureVerifier(): SignatureVerifier = EdDsaSignatureVerifier(key)
    }

    private class EdDsaPrivateKey(
        key: CPointer<EVP_PKEY>,
        private val curve: EdDSA.Curve,
    ) : EdDSA.PrivateKey, Openssl3PrivateKeyEncodable<EdDSA.PrivateKey.Format>(key) {
        override fun outputType(format: EdDSA.PrivateKey.Format): String = when (format) {
            EdDSA.PrivateKey.Format.DER -> "DER"
            EdDSA.PrivateKey.Format.PEM -> "PEM"
            EdDSA.PrivateKey.Format.JWK,
            EdDSA.PrivateKey.Format.RAW -> error("should not be called: handled explicitly in encodeToBlocking")
        }

        override fun encodeToByteArrayBlocking(format: EdDSA.PrivateKey.Format): ByteArray = when (format) {
            EdDSA.PrivateKey.Format.RAW -> unwrapPrivateKeyInfo(
                oid(curve),
                super.encodeToByteArrayBlocking(EdDSA.PrivateKey.Format.DER)
            )
            else -> super.encodeToByteArrayBlocking(format)
        }

        override fun signatureGenerator(): SignatureGenerator = EdDsaSignatureGenerator(key)
    }
}

@OptIn(ExperimentalNativeApi::class, UnsafeNumber::class)
private class EdDsaSignatureGenerator(
    private val privateKey: CPointer<EVP_PKEY>,
) : SignatureGenerator {
    private val cleaner = privateKey.upRef().cleaner()

    override fun createSignFunction(): SignFunction = EdDsaSignFunction(privateKey)

    override fun generateSignatureBlocking(data: ByteArray): ByteArray = memScoped {
        val ctx = checkError(EVP_MD_CTX_new())
        try {
            checkError(
                EVP_DigestSignInit_ex(
                    ctx = ctx,
                    pctx = null,
                    mdname = null, // must be null for EdDSA one-shot
                    libctx = null,
                    props = null,
                    pkey = privateKey,
                    params = null
                )
            )

            data.usePinned {
                val siglen = alloc<size_tVar>()
                checkError(EVP_DigestSign(ctx, null, siglen.ptr, it.safeAddressOfU(0), data.size.convert()))
                val out = ByteArray(siglen.value.convert())
                out.usePinned { outPin ->
                    checkError(EVP_DigestSign(ctx, outPin.safeAddressOfU(0), siglen.ptr, it.safeAddressOfU(0), data.size.convert()))
                }
                out.ensureSizeExactly(siglen.value.convert())
            }
        } finally {
            EVP_MD_CTX_free(ctx)
        }
    }
}

@OptIn(ExperimentalNativeApi::class, UnsafeNumber::class)
private class EdDsaSignatureVerifier(
    private val publicKey: CPointer<EVP_PKEY>,
) : SignatureVerifier {
    private val cleaner = publicKey.upRef().cleaner()

    override fun createVerifyFunction(): VerifyFunction = EdDsaVerifyFunction(publicKey)
}

@OptIn(UnsafeNumber::class)
private class EdDsaSignFunction(
    private val privateKey: CPointer<EVP_PKEY>,
) : SignFunction {
    private var isClosed = false
    private var accumulator = EmptyByteArray

    private fun ensureOpen() = check(!isClosed) { "Already closed" }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        ensureOpen()
        checkBounds(source.size, startIndex, endIndex)
        accumulator += source.copyOfRange(startIndex, endIndex)
    }

    override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        val sig = signToByteArray()
        sig.copyInto(destination, destinationOffset)
        return sig.size
    }

    override fun signToByteArray(): ByteArray {
        ensureOpen()
        return memScoped {
            val ctx = checkError(EVP_MD_CTX_new())
            try {
                checkError(
                    EVP_DigestSignInit_ex(
                        ctx = ctx,
                        pctx = null,
                        mdname = null,
                        libctx = null,
                        props = null,
                        pkey = privateKey,
                        params = null
                    )
                )
                accumulator.usePinned { pin ->
                    val siglen = alloc<size_tVar>()
                    checkError(EVP_DigestSign(ctx, null, siglen.ptr, pin.safeAddressOfU(0), accumulator.size.convert()))
                    val out = ByteArray(siglen.value.convert())
                    out.usePinned { outPin ->
                        checkError(EVP_DigestSign(ctx, outPin.safeAddressOfU(0), siglen.ptr, pin.safeAddressOfU(0), accumulator.size.convert()))
                    }
                    out.ensureSizeExactly(siglen.value.convert())
                }
            } finally {
                EVP_MD_CTX_free(ctx)
                reset()
            }
        }
    }

    override fun reset() {
        ensureOpen()
        accumulator = EmptyByteArray
    }

    override fun close() {
        isClosed = true
        accumulator = EmptyByteArray
    }
}

@OptIn(UnsafeNumber::class)
private class EdDsaVerifyFunction(
    private val publicKey: CPointer<EVP_PKEY>,
) : VerifyFunction {
    private var isClosed = false
    private var accumulator = EmptyByteArray

    private fun ensureOpen() = check(!isClosed) { "Already closed" }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        ensureOpen()
        checkBounds(source.size, startIndex, endIndex)
        accumulator += source.copyOfRange(startIndex, endIndex)
    }

    override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
        ensureOpen()
        checkBounds(signature.size, startIndex, endIndex)
        return memScoped {
            val ctx = checkError(EVP_MD_CTX_new())
            try {
                checkError(
                    EVP_DigestVerifyInit_ex(
                        ctx = ctx,
                        pctx = null,
                        mdname = null,
                        libctx = null,
                        props = null,
                        pkey = publicKey,
                        params = null
                    )
                )
                signature.usePinned { sigPin ->
                    accumulator.usePinned { dataPin ->
                        val res = EVP_DigestVerify(
                            ctx,
                            sigPin.safeAddressOfU(startIndex),
                            (endIndex - startIndex).convert(),
                            dataPin.safeAddressOfU(0),
                            accumulator.size.convert()
                        )
                        if (res != 0) checkError(res)
                        res == 1
                    }
                }
            } finally {
                EVP_MD_CTX_free(ctx)
                reset()
            }
        }
    }

    override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
        check(tryVerify(signature, startIndex, endIndex)) { "Invalid signature" }
    }

    override fun reset() {
        ensureOpen()
        accumulator = EmptyByteArray
    }

    override fun close() {
        isClosed = true
        accumulator = EmptyByteArray
    }
}
