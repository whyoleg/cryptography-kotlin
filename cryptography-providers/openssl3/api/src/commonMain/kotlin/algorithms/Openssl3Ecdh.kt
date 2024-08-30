/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import kotlinx.cinterop.*
import kotlinx.io.bytestring.*
import kotlinx.io.bytestring.unsafe.*
import platform.posix.*

internal object Openssl3Ecdh : ECDH {
    override fun publicKeyDecoder(curve: EC.Curve): KeyDecoder<EC.PublicKey.Format, ECDH.PublicKey> = EcPublicKeyDecoder(curve)

    override fun privateKeyDecoder(curve: EC.Curve): KeyDecoder<EC.PrivateKey.Format, ECDH.PrivateKey> = EcPrivateKeyDecoder(curve)

    override fun keyPairGenerator(curve: EC.Curve): KeyGenerator<ECDH.KeyPair> = EcKeyGenerator(curve)

    private class EcPrivateKeyDecoder(
        private val curve: EC.Curve,
    ) : Openssl3PrivateKeyDecoder<EC.PrivateKey.Format, ECDH.PrivateKey>("EC") {
        override fun inputType(format: EC.PrivateKey.Format): String = when (format) {
            EC.PrivateKey.Format.DER, EC.PrivateKey.Format.DER.SEC1 -> "DER"
            EC.PrivateKey.Format.PEM, EC.PrivateKey.Format.PEM.SEC1 -> "PEM"
            EC.PrivateKey.Format.RAW -> "DER" // with custom processing
            EC.PrivateKey.Format.JWK                                -> error("JWK format is not supported")
        }

        override fun inputStruct(format: EC.PrivateKey.Format): String = when (format) {
            EC.PrivateKey.Format.DER.SEC1, EC.PrivateKey.Format.PEM.SEC1 -> "EC"
            EC.PrivateKey.Format.RAW -> "EC" // with custom processing
            else                                                         -> super.inputStruct(format)
        }

        override fun decodeFromBlocking(format: EC.PrivateKey.Format, data: ByteArray): ECDH.PrivateKey = when (format) {
            EC.PrivateKey.Format.RAW -> super.decodeFromBlocking(format, convertPrivateRawKeyToSec1(curve, data))
            else                     -> super.decodeFromBlocking(format, data)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): ECDH.PrivateKey {
            EC_check_key_group(key, curve)
            return EcPrivateKey(key)
        }
    }

    private class EcPublicKeyDecoder(
        private val curve: EC.Curve,
    ) : Openssl3PublicKeyDecoder<EC.PublicKey.Format, ECDH.PublicKey>("EC") {
        override fun inputType(format: EC.PublicKey.Format): String = when (format) {
            EC.PublicKey.Format.DER -> "DER"
            EC.PublicKey.Format.PEM -> "PEM"
            EC.PublicKey.Format.RAW -> error("should not be called: handled explicitly in decodeFromBlocking")
            EC.PublicKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun decodeFromBlocking(format: EC.PublicKey.Format, data: ByteArray): ECDH.PublicKey = when (format) {
            EC.PublicKey.Format.RAW -> wrapKey(decodePublicRawKey(curve, data))
            else                    -> super.decodeFromBlocking(format, data)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): ECDH.PublicKey {
            EC_check_key_group(key, curve)
            return EcPublicKey(key)
        }
    }

    private class EcKeyGenerator(
        private val curve: EC.Curve,
    ) : Openssl3KeyPairGenerator<ECDH.KeyPair>("EC") {
        @OptIn(UnsafeNumber::class)
        override fun MemScope.createParams(): CValuesRef<OSSL_PARAM> = OSSL_PARAM_array(
            OSSL_PARAM_construct_utf8_string("group".cstr.ptr, curve.name.cstr.ptr, 0.convert())
        )

        override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): ECDH.KeyPair = EcKeyPair(
            publicKey = EcPublicKey(keyPair),
            privateKey = EcPrivateKey(keyPair)
        )
    }

    private class EcKeyPair(
        override val publicKey: ECDH.PublicKey,
        override val privateKey: ECDH.PrivateKey,
    ) : ECDH.KeyPair

    private class EcPrivateKey(
        key: CPointer<EVP_PKEY>,
    ) : ECDH.PrivateKey, Openssl3PrivateKeyEncodable<EC.PrivateKey.Format>(key), SharedSecretGenerator<ECDH.PublicKey> {
        override fun outputType(format: EC.PrivateKey.Format): String = when (format) {
            EC.PrivateKey.Format.DER, EC.PrivateKey.Format.DER.SEC1 -> "DER"
            EC.PrivateKey.Format.PEM, EC.PrivateKey.Format.PEM.SEC1 -> "PEM"
            EC.PrivateKey.Format.RAW -> error("should not be called: handled explicitly in encodeToBlocking")
            EC.PrivateKey.Format.JWK                                -> error("JWK format is not supported")
        }

        override fun outputStruct(format: EC.PrivateKey.Format): String = when (format) {
            EC.PrivateKey.Format.DER.SEC1, EC.PrivateKey.Format.PEM.SEC1 -> "EC"
            else                                                         -> super.outputStruct(format)
        }

        override fun encodeToBlocking(format: EC.PrivateKey.Format): ByteArray = when (format) {
            EC.PrivateKey.Format.RAW -> encodePrivateRawKey(key)
            else                     -> super.encodeToBlocking(format)
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<ECDH.PublicKey> = this

        override fun generateSharedSecretBlocking(other: ECDH.PublicKey): ByteString {
            check(other is EcPublicKey)

            return deriveSharedSecret(publicKey = other.key, privateKey = key)
        }
    }

    private class EcPublicKey(
        key: CPointer<EVP_PKEY>,
    ) : ECDH.PublicKey, Openssl3PublicKeyEncodable<EC.PublicKey.Format>(key), SharedSecretGenerator<ECDH.PrivateKey> {
        override fun outputType(format: EC.PublicKey.Format): String = when (format) {
            EC.PublicKey.Format.DER -> "DER"
            EC.PublicKey.Format.PEM -> "PEM"
            EC.PublicKey.Format.RAW -> error("should not be called: handled explicitly in encodeToBlocking")
            EC.PublicKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun encodeToBlocking(format: EC.PublicKey.Format): ByteArray = when (format) {
            EC.PublicKey.Format.RAW -> encodePublicRawKey(key)
            else                    -> super.encodeToBlocking(format)
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<ECDH.PrivateKey> = this

        override fun generateSharedSecretBlocking(other: ECDH.PrivateKey): ByteString {
            check(other is EcPrivateKey)

            return deriveSharedSecret(publicKey = key, privateKey = other.key)
        }
    }
}

@OptIn(UnsafeNumber::class, UnsafeByteStringApi::class)
private fun deriveSharedSecret(
    publicKey: CPointer<EVP_PKEY>,
    privateKey: CPointer<EVP_PKEY>,
): ByteString = memScoped {
    val context = checkError(EVP_PKEY_CTX_new_from_pkey(null, privateKey, null))
    try {
        checkError(EVP_PKEY_derive_init(context))
        checkError(EVP_PKEY_derive_set_peer(context, publicKey))
        val secretSize = alloc<size_tVar>()
        checkError(EVP_PKEY_derive(context, null, secretSize.ptr))
        val secret = ByteArray(secretSize.value.toInt())
        checkError(EVP_PKEY_derive(context, secret.refToU(0), secretSize.ptr))
        UnsafeByteStringOperations.wrapUnsafe(secret)
    } finally {
        EVP_PKEY_CTX_free(context)
    }
}
