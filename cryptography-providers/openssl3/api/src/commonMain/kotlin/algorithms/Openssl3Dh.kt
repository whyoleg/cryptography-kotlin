/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.cinterop.*
import platform.posix.*

internal object Openssl3Dh : DH {
    override fun publicKeyDecoder(parameters: DH.Parameters): KeyDecoder<DH.PublicKey.Format, DH.PublicKey> =
        DhPublicKeyDecoder(parameters)

    override fun privateKeyDecoder(parameters: DH.Parameters): KeyDecoder<DH.PrivateKey.Format, DH.PrivateKey> =
        DhPrivateKeyDecoder(parameters)

    override fun keyPairGenerator(parameters: DH.Parameters): KeyGenerator<DH.KeyPair> =
        DhKeyPairGenerator(parameters)

    override fun parametersDecoder(): KeyDecoder<DH.Parameters.Format, DH.Parameters> =
        DhParametersDecoder()

    override fun parametersGenerator(keySize: Int): KeyGenerator<DH.Parameters> =
        DhParametersGenerator(keySize)

    private class DhParametersGenerator(
        private val keySize: Int,
    ) : Openssl3KeyPairGenerator<DH.Parameters>("DH") {
        @OptIn(UnsafeNumber::class)
        override fun MemScope.createParams(): CValuesRef<OSSL_PARAM> = OSSL_PARAM_array(
            OSSL_PARAM_construct_int("group".cstr.ptr, alloc<IntVar> { value = keySize }.ptr),
            OSSL_PARAM_construct_end()
        )

        override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): DH.Parameters {
            return DhParameters(keyPair)
        }
    }

    private class DhParametersDecoder : KeyDecoder<DH.Parameters.Format, DH.Parameters> {
        override suspend fun decodeFromByteArray(format: DH.Parameters.Format, bytes: ByteArray): DH.Parameters =
            decodeFromByteArrayBlocking(format, bytes)

        override fun decodeFromByteArrayBlocking(format: DH.Parameters.Format, bytes: ByteArray): DH.Parameters = when (format) {
            DH.Parameters.Format.DER -> decodeFromDer(bytes)
            DH.Parameters.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.DHParams, bytes))
        }

        private fun decodeFromDer(bytes: ByteArray): DH.Parameters = memScoped {
            val pkeyVar = alloc<CPointerVar<EVP_PKEY>>()
            val context = checkError(
                OSSL_DECODER_CTX_new_for_pkey(
                    pkey = pkeyVar.ptr,
                    input_type = "DER".cstr.ptr,
                    input_struct = "DH".cstr.ptr,
                    keytype = "DH".cstr.ptr,
                    selection = OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
                    libctx = null,
                    propquery = null
                )
            )
            @OptIn(UnsafeNumber::class)
            try {
                val pdataLenVar = alloc(bytes.size.convert<size_t>())
                val pdataVar = alloc<CPointerVar<UByteVar>> { value = allocArrayOf(bytes).reinterpret() }
                checkError(OSSL_DECODER_from_data(context, pdataVar.ptr, pdataLenVar.ptr))
                val pkey = checkError(pkeyVar.value)
                DhParameters(pkey)
            } finally {
                OSSL_DECODER_CTX_free(context)
            }
        }
    }

    private class DhKeyPairGenerator(
        private val parameters: DH.Parameters,
    ) : KeyGenerator<DH.KeyPair> {
        override suspend fun generateKey(): DH.KeyPair = generateKeyBlocking()

        @OptIn(UnsafeNumber::class)
        override fun generateKeyBlocking(): DH.KeyPair = memScoped {
            require(parameters is DhParameters) { "Only OpenSSL DH parameters are supported" }
            
            val context = checkError(EVP_PKEY_CTX_new(parameters.key, null))
            try {
                checkError(EVP_PKEY_keygen_init(context))
                
                val keyPair = alloc<CPointerVar<EVP_PKEY>>()
                checkError(EVP_PKEY_keygen(context, keyPair.ptr))
                
                DhKeyPair(
                    publicKey = DhPublicKey(keyPair.value!!),
                    privateKey = DhPrivateKey(keyPair.value!!)
                )
            } finally {
                EVP_PKEY_CTX_free(context)
            }
        }
    }

    private class DhPublicKeyDecoder(
        private val parameters: DH.Parameters,
    ) : Openssl3PublicKeyDecoder<DH.PublicKey.Format, DH.PublicKey>("DH") {
        override fun wrapKey(key: CPointer<EVP_PKEY>): DH.PublicKey {
            // Verify that the key matches the expected parameters
            require(parameters is DhParameters) { "Only OpenSSL DH parameters are supported" }
            // TODO: Add parameter validation if needed
            return DhPublicKey(key)
        }
    }

    private class DhPrivateKeyDecoder(
        private val parameters: DH.Parameters,
    ) : Openssl3PrivateKeyDecoder<DH.PrivateKey.Format, DH.PrivateKey>("DH") {
        override fun wrapKey(key: CPointer<EVP_PKEY>): DH.PrivateKey {
            // Verify that the key matches the expected parameters
            require(parameters is DhParameters) { "Only OpenSSL DH parameters are supported" }
            // TODO: Add parameter validation if needed
            return DhPrivateKey(key)
        }
    }

    private class DhParameters(
        val key: CPointer<EVP_PKEY>
    ) : DH.Parameters, Openssl3KeyEncodable<DH.Parameters.Format>(key) {
        override fun selection(format: DH.Parameters.Format): Int = OSSL_KEYMGMT_SELECT_ALL_PARAMETERS
        
        override fun outputType(format: DH.Parameters.Format): String = when (format) {
            DH.Parameters.Format.DER -> "DER"
            DH.Parameters.Format.PEM -> "PEM"
        }

        override fun outputStruct(format: DH.Parameters.Format): String = "DH"

        override fun encodeToByteArrayBlocking(format: DH.Parameters.Format): ByteArray = when (format) {
            DH.Parameters.Format.DER -> super.encodeToByteArrayBlocking(format)
            DH.Parameters.Format.PEM -> wrapPem(PemLabel.DHParams, super.encodeToByteArrayBlocking(DH.Parameters.Format.DER))
        }
    }

    private class DhKeyPair(
        override val publicKey: DH.PublicKey,
        override val privateKey: DH.PrivateKey,
    ) : DH.KeyPair

    private class DhPublicKey(
        key: CPointer<EVP_PKEY>,
    ) : DH.PublicKey, Openssl3PublicKeyEncodable<DH.PublicKey.Format>(key), SharedSecretGenerator<DH.PrivateKey> {
        override fun sharedSecretGenerator(): SharedSecretGenerator<DH.PrivateKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: DH.PrivateKey): ByteArray {
            check(other is DhPrivateKey) { "Only OpenSSL DH private keys are supported" }
            return deriveSharedSecret(publicKey = key, privateKey = other.key)
        }
    }

    private class DhPrivateKey(
        key: CPointer<EVP_PKEY>,
    ) : DH.PrivateKey, Openssl3PrivateKeyEncodable<DH.PrivateKey.Format>(key), SharedSecretGenerator<DH.PublicKey> {
        override fun sharedSecretGenerator(): SharedSecretGenerator<DH.PublicKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: DH.PublicKey): ByteArray {
            check(other is DhPublicKey) { "Only OpenSSL DH public keys are supported" }
            return deriveSharedSecret(publicKey = other.key, privateKey = key)
        }
    }
}

@OptIn(UnsafeNumber::class)
private fun deriveSharedSecret(
    publicKey: CPointer<EVP_PKEY>,
    privateKey: CPointer<EVP_PKEY>,
): ByteArray = memScoped {
    val context = checkError(EVP_PKEY_CTX_new(privateKey, null))
    try {
        checkError(EVP_PKEY_derive_init(context))
        checkError(EVP_PKEY_derive_set_peer(context, publicKey))
        
        val secretSize = alloc<size_tVar>()
        checkError(EVP_PKEY_derive(context, null, secretSize.ptr))
        
        val secret = ByteArray(secretSize.value.toInt())
        checkError(EVP_PKEY_derive(context, secret.refToU(0), secretSize.ptr))
        secret
    } finally {
        EVP_PKEY_CTX_free(context)
    }
}