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

internal object Openssl3XDH : XDH {
    private fun algorithmName(curve: XDH.Curve): String = when (curve) {
        XDH.Curve.X25519 -> "X25519"
        XDH.Curve.X448   -> "X448"
    }

    override fun publicKeyDecoder(curve: XDH.Curve): KeyDecoder<XDH.PublicKey.Format, XDH.PublicKey> =
        object : Openssl3PublicKeyDecoder<XDH.PublicKey.Format, XDH.PublicKey>(algorithmName(curve)) {
            override fun inputType(format: XDH.PublicKey.Format): String = when (format) {
                XDH.PublicKey.Format.DER -> "DER"
                XDH.PublicKey.Format.PEM -> "PEM"
                XDH.PublicKey.Format.JWK,
                XDH.PublicKey.Format.RAW -> error("$format format is not supported")
            }

            override fun wrapKey(key: CPointer<EVP_PKEY>): XDH.PublicKey = XdhPublicKey(key)
        }

    override fun privateKeyDecoder(curve: XDH.Curve): KeyDecoder<XDH.PrivateKey.Format, XDH.PrivateKey> =
        object : Openssl3PrivateKeyDecoder<XDH.PrivateKey.Format, XDH.PrivateKey>(algorithmName(curve)) {
            override fun inputType(format: XDH.PrivateKey.Format): String = when (format) {
                XDH.PrivateKey.Format.DER -> "DER"
                XDH.PrivateKey.Format.PEM -> "PEM"
                XDH.PrivateKey.Format.JWK,
                XDH.PrivateKey.Format.RAW -> error("$format format is not supported")
            }

            override fun wrapKey(key: CPointer<EVP_PKEY>): XDH.PrivateKey = XdhPrivateKey(key)
        }

    override fun keyPairGenerator(curve: XDH.Curve): KeyGenerator<XDH.KeyPair> =
        object : Openssl3KeyPairGenerator<XDH.KeyPair>(algorithmName(curve)) {
            override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
            override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): XDH.KeyPair = XdhKeyPair(
                publicKey = XdhPublicKey(keyPair),
                privateKey = XdhPrivateKey(keyPair)
            )
        }

    private class XdhKeyPair(
        override val publicKey: XDH.PublicKey,
        override val privateKey: XDH.PrivateKey,
    ) : XDH.KeyPair

    private class XdhPublicKey(
        key: CPointer<EVP_PKEY>,
    ) : XDH.PublicKey, Openssl3PublicKeyEncodable<XDH.PublicKey.Format>(key), SharedSecretGenerator<XDH.PrivateKey> {
        override fun outputType(format: XDH.PublicKey.Format): String = when (format) {
            XDH.PublicKey.Format.DER -> "DER"
            XDH.PublicKey.Format.PEM -> "PEM"
            XDH.PublicKey.Format.JWK,
            XDH.PublicKey.Format.RAW -> error("$format format is not supported")
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PrivateKey> = this
        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PrivateKey): ByteArray {
            check(other is XdhPrivateKey)
            return deriveSharedSecret(publicKey = key, privateKey = other.key)
        }
    }

    private class XdhPrivateKey(
        key: CPointer<EVP_PKEY>,
    ) : XDH.PrivateKey, Openssl3PrivateKeyEncodable<XDH.PrivateKey.Format>(key), SharedSecretGenerator<XDH.PublicKey> {
        override fun outputType(format: XDH.PrivateKey.Format): String = when (format) {
            XDH.PrivateKey.Format.DER -> "DER"
            XDH.PrivateKey.Format.PEM -> "PEM"
            XDH.PrivateKey.Format.JWK,
            XDH.PrivateKey.Format.RAW -> error("$format format is not supported")
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PublicKey> = this
        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PublicKey): ByteArray {
            check(other is XdhPublicKey)
            return deriveSharedSecret(publicKey = other.key, privateKey = key)
        }
    }
}

@OptIn(UnsafeNumber::class)
private fun deriveSharedSecret(
    publicKey: CPointer<EVP_PKEY>,
    privateKey: CPointer<EVP_PKEY>,
): ByteArray = memScoped {
    val context = checkError(EVP_PKEY_CTX_new_from_pkey(null, privateKey, null))
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
