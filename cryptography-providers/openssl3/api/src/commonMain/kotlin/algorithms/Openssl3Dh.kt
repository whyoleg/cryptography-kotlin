/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.DH
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*

internal object Openssl3Dh : DH {
    override fun publicKeyDecoder(): Decoder<DH.PublicKey.Format, DH.PublicKey> = DhPublicKeyDecoder

    override fun privateKeyDecoder(): Decoder<DH.PrivateKey.Format, DH.PrivateKey> = DhPrivateKeyDecoder

    override fun parametersDecoder(): Decoder<DH.Parameters.Format, DH.Parameters> = DhParametersDecoder

    override fun parametersGenerator(primeSize: BinarySize, privateValueSize: BinarySize?): DH.ParametersGenerator =
        DhParametersGenerator(primeSize.inBits.toUInt(), privateValueSize?.inBits)

    private object DhPrivateKeyDecoder : Openssl3PrivateKeyDecoder<DH.PrivateKey.Format, DH.PrivateKey>("DH") {
        override fun inputType(format: DH.PrivateKey.Format): String = when (format) {
            DH.PrivateKey.Format.DER -> "DER"
            DH.PrivateKey.Format.PEM -> "PEM"
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): DH.PrivateKey {
            return DhPrivateKey(key, publicKey = null)
        }
    }

    private object DhPublicKeyDecoder : Openssl3PublicKeyDecoder<DH.PublicKey.Format, DH.PublicKey>("DH") {
        override fun inputType(format: DH.PublicKey.Format): String = when (format) {
            DH.PublicKey.Format.DER -> "DER"
            DH.PublicKey.Format.PEM -> "PEM"
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): DH.PublicKey {
            return DhPublicKey(key)
        }
    }

    private class DhKeyGenerator(key: CPointer<EVP_PKEY>) : Openssl3KeyPairGenerator<DH.KeyPair>(key) {
        override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
        override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): DH.KeyPair {
            val publicKey = DhPublicKey(keyPair)
            return DhKeyPair(
                publicKey = publicKey,
                privateKey = DhPrivateKey(keyPair, publicKey)
            )
        }
    }

    private class DhKeyPair(
        override val publicKey: DH.PublicKey,
        override val privateKey: DH.PrivateKey,
    ) : DH.KeyPair

    private class DhPrivateKey(
        key: CPointer<EVP_PKEY>,
        publicKey: DH.PublicKey?,
    ) : DH.PrivateKey,
        Openssl3PrivateKeyEncodable<DH.PrivateKey.Format, DH.PublicKey>(key, publicKey),
        SharedSecretGenerator<DH.PublicKey> {
        override fun wrapPublicKey(key: CPointer<EVP_PKEY>): DH.PublicKey = DhPublicKey(key)

        override fun outputType(format: DH.PrivateKey.Format): String = when (format) {
            DH.PrivateKey.Format.DER -> "DER"
            DH.PrivateKey.Format.PEM -> "PEM"
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<DH.PublicKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: DH.PublicKey): ByteArray {
            check(other is DhPublicKey)

            return deriveSharedSecret(publicKey = other.key, privateKey = key) {
                // enable padding
                OSSL_PARAM_array(OSSL_PARAM_construct_uint("pad".cstr.ptr, alloc(1.toUInt()).ptr))
            }
        }
    }

    private class DhPublicKey(
        key: CPointer<EVP_PKEY>,
    ) : DH.PublicKey, Openssl3PublicKeyEncodable<DH.PublicKey.Format>(key), SharedSecretGenerator<DH.PrivateKey> {

        override fun outputType(format: DH.PublicKey.Format): String = when (format) {
            DH.PublicKey.Format.DER -> "DER"
            DH.PublicKey.Format.PEM -> "PEM"
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<DH.PrivateKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: DH.PrivateKey): ByteArray {
            check(other is DhPrivateKey)

            return deriveSharedSecret(publicKey = key, privateKey = other.key) {
                // enable padding
                OSSL_PARAM_array(OSSL_PARAM_construct_uint("pad".cstr.ptr, alloc(1.toUInt()).ptr))
            }
        }
    }

    private object DhParametersDecoder : Openssl3ParametersDecoder<DH.Parameters.Format, DH.Parameters>("DH") {
        override fun inputType(format: DH.Parameters.Format): String = when (format) {
            DH.Parameters.Format.DER -> "DER"
            DH.Parameters.Format.PEM -> "PEM"
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): DH.Parameters {
            return Openssl3DhParameters(key)
        }
    }

    private class DhParametersGenerator(
        private val primeSizeBits: UInt,
        private val privateValueLengthBits: Int?,
    ) : DH.ParametersGenerator {
        @OptIn(UnsafeNumber::class)
        override fun generateParametersBlocking(): DH.Parameters = with_PKEY_CTX("DH") { context ->
            checkError(EVP_PKEY_paramgen_init(context))

            checkError(
                EVP_PKEY_CTX_set_params(
                    context,
                    OSSL_PARAM_array(
                        OSSL_PARAM_construct_uint("pbits".cstr.ptr, alloc(primeSizeBits).ptr),
                        privateValueLengthBits?.let { OSSL_PARAM_construct_int("priv_len".cstr.ptr, alloc(it).ptr) },
                    )
                )
            )

            val paramsKeyVar = alloc<CPointerVar<EVP_PKEY>>()
            checkError(EVP_PKEY_generate(context, paramsKeyVar.ptr))
            val paramsKey = checkError(paramsKeyVar.value)
            Openssl3DhParameters(paramsKey)
        }
    }

    private class Openssl3DhParameters(
        key: CPointer<EVP_PKEY>,
    ) : DH.Parameters, Openssl3ParametersEncodable<DH.Parameters.Format>(key) {
        override fun keyPairGenerator(): KeyGenerator<DH.KeyPair> = DhKeyGenerator(key)

        override fun outputType(format: DH.Parameters.Format): String = when (format) {
            DH.Parameters.Format.DER -> "DER"
            DH.Parameters.Format.PEM -> "PEM"
        }
    }
}
