/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swift.DwcCryptoKitInterop.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.serialization.builtins.*

internal object CryptoKitXdh : XDH {
    override fun publicKeyDecoder(curve: XDH.Curve): KeyDecoder<XDH.PublicKey.Format, XDH.PublicKey> {
        check(curve == XDH.Curve.X25519) { "CryptoKit supports X25519 only" }
        return PublicKeyDecoder
    }

    override fun privateKeyDecoder(curve: XDH.Curve): KeyDecoder<XDH.PrivateKey.Format, XDH.PrivateKey> {
        check(curve == XDH.Curve.X25519) { "CryptoKit supports X25519 only" }
        return PrivateKeyDecoder
    }

    override fun keyPairGenerator(curve: XDH.Curve): KeyGenerator<XDH.KeyPair> {
        check(curve == XDH.Curve.X25519) { "CryptoKit supports X25519 only" }
        return KeyPairGenerator
    }

    private object KeyPairGenerator : KeyGenerator<XDH.KeyPair> {
        override fun generateKeyBlocking(): XDH.KeyPair {
            val privateKey = SwiftXdhPrivateKey.generate()
            return XdhKeyPair(
                publicKey = XdhPublicKey(privateKey.publicKey()),
                privateKey = XdhPrivateKey(privateKey)
            )
        }
    }

    private object PublicKeyDecoder : KeyDecoder<XDH.PublicKey.Format, XDH.PublicKey> {
        override fun decodeFromByteArrayBlocking(format: XDH.PublicKey.Format, bytes: ByteArray): XDH.PublicKey = when (format) {
            XDH.PublicKey.Format.RAW -> XdhPublicKey(
                swiftTry { error -> bytes.useNSData { SwiftXdhPublicKey.decodeRawWithRawRepresentation(it, error) } }
            )
            XDH.PublicKey.Format.DER -> {
                val raw = unwrapSubjectPublicKeyInfo(ObjectIdentifier.X25519, bytes)
                XdhPublicKey(swiftTry { error -> raw.useNSData { SwiftXdhPublicKey.decodeRawWithRawRepresentation(it, error) } })
            }
            XDH.PublicKey.Format.PEM -> {
                val der = unwrapPem(PemLabel.PublicKey, bytes)
                val raw = unwrapSubjectPublicKeyInfo(ObjectIdentifier.X25519, der)
                XdhPublicKey(swiftTry { error -> raw.useNSData { SwiftXdhPublicKey.decodeRawWithRawRepresentation(it, error) } })
            }
            else                     -> error("$format is not supported by CryptoKit XDH")
        }
    }

    private object PrivateKeyDecoder : KeyDecoder<XDH.PrivateKey.Format, XDH.PrivateKey> {
        override fun decodeFromByteArrayBlocking(format: XDH.PrivateKey.Format, bytes: ByteArray): XDH.PrivateKey = when (format) {
            XDH.PrivateKey.Format.RAW -> XdhPrivateKey(
                swiftTry { error -> bytes.useNSData { SwiftXdhPrivateKey.decodeRawWithRawRepresentation(it, error) } }
            )
            XDH.PrivateKey.Format.DER -> {
                val raw = unwrapPrivateKeyInfoForEdDsaXdh(ObjectIdentifier.X25519, bytes)
                XdhPrivateKey(swiftTry { error -> raw.useNSData { SwiftXdhPrivateKey.decodeRawWithRawRepresentation(it, error) } })
            }
            XDH.PrivateKey.Format.PEM -> {
                val der = unwrapPem(PemLabel.PrivateKey, bytes)
                val raw = unwrapPrivateKeyInfoForEdDsaXdh(ObjectIdentifier.X25519, der)
                XdhPrivateKey(swiftTry { error -> raw.useNSData { SwiftXdhPrivateKey.decodeRawWithRawRepresentation(it, error) } })
            }
            else                      -> error("$format is not supported by CryptoKit XDH")
        }
    }

    private class XdhKeyPair(
        override val publicKey: XDH.PublicKey,
        override val privateKey: XDH.PrivateKey,
    ) : XDH.KeyPair

    private class XdhPublicKey(
        val key: SwiftXdhPublicKey,
    ) : XDH.PublicKey, SharedSecretGenerator<XDH.PrivateKey> {
        override fun encodeToByteArrayBlocking(format: XDH.PublicKey.Format): ByteArray = when (format) {
            XDH.PublicKey.Format.RAW -> key.rawRepresentation().toByteArray()
            XDH.PublicKey.Format.DER -> wrapSubjectPublicKeyInfo(
                UnknownKeyAlgorithmIdentifier(ObjectIdentifier.X25519),
                key.rawRepresentation().toByteArray()
            )
            XDH.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToByteArrayBlocking(XDH.PublicKey.Format.DER))
            else                     -> error("$format is not supported by CryptoKit XDH")
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PrivateKey> = this
        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PrivateKey): ByteArray {
            require(other is XdhPrivateKey)
            return swiftTry { error -> other.key.deriveSecretWith(key, error) }.toByteArray()
        }
    }

    private class XdhPrivateKey(
        val key: SwiftXdhPrivateKey,
    ) : XDH.PrivateKey, SharedSecretGenerator<XDH.PublicKey> {
        override fun getPublicKeyBlocking(): XDH.PublicKey = XdhPublicKey(key.publicKey())

        override fun encodeToByteArrayBlocking(format: XDH.PrivateKey.Format): ByteArray = when (format) {
            XDH.PrivateKey.Format.RAW -> key.rawRepresentation().toByteArray()
            XDH.PrivateKey.Format.DER -> {
                // EdDSA/XDH private keys in PKCS#8 need to be wrapped in OCTET STRING
                val rawKey = key.rawRepresentation().toByteArray()
                val wrappedKey = Der.encodeToByteArray(ByteArraySerializer(), rawKey)
                wrapPrivateKeyInfo(0, UnknownKeyAlgorithmIdentifier(ObjectIdentifier.X25519), wrappedKey)
            }
            XDH.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToByteArrayBlocking(XDH.PrivateKey.Format.DER))
            else                      -> error("$format is not supported by CryptoKit XDH")
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PublicKey> = this
        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PublicKey): ByteArray {
            require(other is XdhPublicKey)
            return swiftTry { error -> key.deriveSecretWith(other.key, error) }.toByteArray()
        }
    }
}
