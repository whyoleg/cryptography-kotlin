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
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.asn1.ObjectIdentifier
import dev.whyoleg.cryptography.providers.base.materials.*

internal object Openssl3XDH : XDH {
    private fun algorithmName(curve: XDH.Curve): String = when (curve) {
        XDH.Curve.X25519 -> "X25519"
        XDH.Curve.X448   -> "X448"
    }
    private fun oid(curve: XDH.Curve): ObjectIdentifier = when (curve) {
        XDH.Curve.X25519 -> ObjectIdentifier.X25519
        XDH.Curve.X448   -> ObjectIdentifier.X448
    }

    override fun publicKeyDecoder(curve: XDH.Curve): KeyDecoder<XDH.PublicKey.Format, XDH.PublicKey> =
        object : Openssl3PublicKeyDecoder<XDH.PublicKey.Format, XDH.PublicKey>(algorithmName(curve)) {
            override fun inputType(format: XDH.PublicKey.Format): String = when (format) {
                XDH.PublicKey.Format.DER -> "DER"
                XDH.PublicKey.Format.PEM -> "PEM"
                XDH.PublicKey.Format.JWK,
                XDH.PublicKey.Format.RAW -> error("should not be called: handled explicitly in decodeFromBlocking")
            }

            override fun decodeFromByteArrayBlocking(format: XDH.PublicKey.Format, bytes: ByteArray): XDH.PublicKey = when (format) {
                XDH.PublicKey.Format.RAW -> super.decodeFromByteArrayBlocking(
                    XDH.PublicKey.Format.DER,
                    wrapSubjectPublicKeyInfo(UnknownKeyAlgorithmIdentifier(oid(curve)), bytes)
                )
                else -> super.decodeFromByteArrayBlocking(format, bytes)
            }

            override fun wrapKey(key: CPointer<EVP_PKEY>): XDH.PublicKey = XdhPublicKey(key, curve)
        }

    override fun privateKeyDecoder(curve: XDH.Curve): KeyDecoder<XDH.PrivateKey.Format, XDH.PrivateKey> =
        object : Openssl3PrivateKeyDecoder<XDH.PrivateKey.Format, XDH.PrivateKey>(algorithmName(curve)) {
            override fun inputType(format: XDH.PrivateKey.Format): String = when (format) {
                XDH.PrivateKey.Format.DER -> "DER"
                XDH.PrivateKey.Format.PEM -> "PEM"
                XDH.PrivateKey.Format.JWK,
                XDH.PrivateKey.Format.RAW -> error("should not be called: handled explicitly in decodeFromBlocking")
            }

            override fun decodeFromByteArrayBlocking(format: XDH.PrivateKey.Format, bytes: ByteArray): XDH.PrivateKey = when (format) {
                XDH.PrivateKey.Format.RAW -> super.decodeFromByteArrayBlocking(
                    XDH.PrivateKey.Format.DER,
                    wrapPrivateKeyInfo(0, UnknownKeyAlgorithmIdentifier(oid(curve)), bytes)
                )
                else -> super.decodeFromByteArrayBlocking(format, bytes)
            }

            override fun wrapKey(key: CPointer<EVP_PKEY>): XDH.PrivateKey = XdhPrivateKey(key, curve)
        }

    override fun keyPairGenerator(curve: XDH.Curve): KeyGenerator<XDH.KeyPair> =
        object : Openssl3KeyPairGenerator<XDH.KeyPair>(algorithmName(curve)) {
            override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
            override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): XDH.KeyPair = XdhKeyPair(
                publicKey = XdhPublicKey(keyPair, curve),
                privateKey = XdhPrivateKey(keyPair, curve)
            )
        }

    private class XdhKeyPair(
        override val publicKey: XDH.PublicKey,
        override val privateKey: XDH.PrivateKey,
    ) : XDH.KeyPair

    private class XdhPublicKey(
        key: CPointer<EVP_PKEY>,
        private val curve: XDH.Curve,
    ) : XDH.PublicKey, Openssl3PublicKeyEncodable<XDH.PublicKey.Format>(key), SharedSecretGenerator<XDH.PrivateKey> {
        override fun outputType(format: XDH.PublicKey.Format): String = when (format) {
            XDH.PublicKey.Format.DER -> "DER"
            XDH.PublicKey.Format.PEM -> "PEM"
            XDH.PublicKey.Format.JWK,
            XDH.PublicKey.Format.RAW -> error("should not be called: handled explicitly in encodeToBlocking")
        }

        override fun encodeToByteArrayBlocking(format: XDH.PublicKey.Format): ByteArray = when (format) {
            XDH.PublicKey.Format.RAW -> unwrapSubjectPublicKeyInfo(oid(curve), super.encodeToByteArrayBlocking(XDH.PublicKey.Format.DER))
            else -> super.encodeToByteArrayBlocking(format)
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PrivateKey> = this
        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PrivateKey): ByteArray {
            check(other is XdhPrivateKey)
            return deriveSharedSecret(publicKey = key, privateKey = other.key)
        }
    }

    private class XdhPrivateKey(
        key: CPointer<EVP_PKEY>,
        private val curve: XDH.Curve,
    ) : XDH.PrivateKey, Openssl3PrivateKeyEncodable<XDH.PrivateKey.Format>(key), SharedSecretGenerator<XDH.PublicKey> {
        override fun outputType(format: XDH.PrivateKey.Format): String = when (format) {
            XDH.PrivateKey.Format.DER -> "DER"
            XDH.PrivateKey.Format.PEM -> "PEM"
            XDH.PrivateKey.Format.JWK,
            XDH.PrivateKey.Format.RAW -> error("should not be called: handled explicitly in encodeToBlocking")
        }

        override fun encodeToByteArrayBlocking(format: XDH.PrivateKey.Format): ByteArray = when (format) {
            XDH.PrivateKey.Format.RAW -> unwrapPrivateKeyInfo(oid(curve), super.encodeToByteArrayBlocking(XDH.PrivateKey.Format.DER))
            else -> super.encodeToByteArrayBlocking(format)
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PublicKey> = this
        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PublicKey): ByteArray {
            check(other is XdhPublicKey)
            return deriveSharedSecret(publicKey = other.key, privateKey = key)
        }
    }
}
