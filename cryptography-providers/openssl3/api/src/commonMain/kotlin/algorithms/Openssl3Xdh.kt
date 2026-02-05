/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*

internal object Openssl3Xdh : XDH {
    override fun publicKeyDecoder(curve: XDH.Curve): Decoder<XDH.PublicKey.Format, XDH.PublicKey> = PublicKeyDecoder(curve)
    override fun privateKeyDecoder(curve: XDH.Curve): Decoder<XDH.PrivateKey.Format, XDH.PrivateKey> = PrivateKeyDecoder(curve)
    override fun keyPairGenerator(curve: XDH.Curve): KeyGenerator<XDH.KeyPair> = KeyPairGenerator(curve)

    private class PublicKeyDecoder(
        private val curve: XDH.Curve,
    ) : Openssl3PublicKeyDecoder<XDH.PublicKey.Format, XDH.PublicKey>(curve.name) {
        override fun inputType(format: XDH.PublicKey.Format): String = when (format) {
            XDH.PublicKey.Format.DER -> "DER"
            XDH.PublicKey.Format.PEM -> "PEM"
            XDH.PublicKey.Format.JWK,
            XDH.PublicKey.Format.RAW,
                                     -> error("should not be called: handled explicitly in decodeFromBlocking")
        }

        override fun decodeFromByteArrayBlocking(format: XDH.PublicKey.Format, bytes: ByteArray): XDH.PublicKey = when (format) {
            XDH.PublicKey.Format.RAW -> {
                val type = when (curve) {
                    XDH.Curve.X25519 -> EVP_PKEY_X25519
                    XDH.Curve.X448   -> EVP_PKEY_X448
                }
                XdhPublicKey(decodeRawPublicKey(type, bytes))
            }
            else                     -> super.decodeFromByteArrayBlocking(format, bytes)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): XDH.PublicKey = XdhPublicKey(key)
    }

    private class PrivateKeyDecoder(
        private val curve: XDH.Curve,
    ) : Openssl3PrivateKeyDecoder<XDH.PrivateKey.Format, XDH.PrivateKey>(curve.name) {
        override fun inputType(format: XDH.PrivateKey.Format): String = when (format) {
            XDH.PrivateKey.Format.DER -> "DER"
            XDH.PrivateKey.Format.PEM -> "PEM"
            XDH.PrivateKey.Format.JWK,
            XDH.PrivateKey.Format.RAW,
                                      -> error("should not be called: handled explicitly in decodeFromBlocking")
        }

        override fun decodeFromByteArrayBlocking(format: XDH.PrivateKey.Format, bytes: ByteArray): XDH.PrivateKey = when (format) {
            XDH.PrivateKey.Format.RAW -> {
                val type = when (curve) {
                    XDH.Curve.X25519 -> EVP_PKEY_X25519
                    XDH.Curve.X448   -> EVP_PKEY_X448
                }
                XdhPrivateKey(decodeRawPrivateKey(type, bytes))
            }
            else                      -> super.decodeFromByteArrayBlocking(format, bytes)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): XDH.PrivateKey = XdhPrivateKey(key)
    }

    private class KeyPairGenerator(
        curve: XDH.Curve,
    ) : Openssl3KeyPairGenerator<XDH.KeyPair>(curve.name) {
        override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
        override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): XDH.KeyPair {
            val publicKey = XdhPublicKey(keyPair)
            return XdhKeyPair(
                publicKey = publicKey,
                privateKey = XdhPrivateKey(keyPair, publicKey)
            )
        }
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
            XDH.PublicKey.Format.RAW,
                                     -> error("should not be called: handled explicitly in encodeToBlocking")
        }

        override fun encodeToByteArrayBlocking(format: XDH.PublicKey.Format): ByteArray = when (format) {
            XDH.PublicKey.Format.RAW -> encodeRawPublicKey(key)
            else                     -> super.encodeToByteArrayBlocking(format)
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PrivateKey> = this
        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PrivateKey): ByteArray {
            check(other is XdhPrivateKey)
            return deriveSharedSecret(publicKey = key, privateKey = other.key)
        }
    }

    private class XdhPrivateKey(
        key: CPointer<EVP_PKEY>,
        publicKey: XDH.PublicKey? = null,
    ) : XDH.PrivateKey, Openssl3PrivateKeyEncodable<XDH.PrivateKey.Format, XDH.PublicKey>(key, publicKey),
        SharedSecretGenerator<XDH.PublicKey> {
        override fun wrapPublicKey(key: CPointer<EVP_PKEY>): XDH.PublicKey = XdhPublicKey(key)

        override fun outputType(format: XDH.PrivateKey.Format): String = when (format) {
            XDH.PrivateKey.Format.DER -> "DER"
            XDH.PrivateKey.Format.PEM -> "PEM"
            XDH.PrivateKey.Format.JWK,
            XDH.PrivateKey.Format.RAW,
                                      -> error("should not be called: handled explicitly in encodeToBlocking")
        }

        override fun encodeToByteArrayBlocking(format: XDH.PrivateKey.Format): ByteArray = when (format) {
            XDH.PrivateKey.Format.RAW -> encodeRawPrivateKey(key)
            else                      -> super.encodeToByteArrayBlocking(format)
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PublicKey> = this
        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PublicKey): ByteArray {
            check(other is XdhPublicKey)
            return deriveSharedSecret(publicKey = other.key, privateKey = key)
        }
    }
}
