/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swiftinterop.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.cinterop.*
import platform.Foundation.*

internal object CryptoKitXDH : XDH {
    override fun publicKeyDecoder(curve: XDH.Curve): KeyDecoder<XDH.PublicKey.Format, XDH.PublicKey> {
        check(curve == XDH.Curve.X25519) { "CryptoKit supports X25519 only" }
        return object : KeyDecoder<XDH.PublicKey.Format, XDH.PublicKey> {
            override fun decodeFromByteArrayBlocking(format: XDH.PublicKey.Format, bytes: ByteArray): XDH.PublicKey = when (format) {
                XDH.PublicKey.Format.RAW -> XPublic(
                    swiftTry<SwiftXdhPublicKey> { error -> bytes.useNSData { SwiftXdhPublicKey.decodeRawWithRawRepresentation(it, error) } }
                )
                XDH.PublicKey.Format.DER -> {
                    val raw = unwrapSubjectPublicKeyInfo(MontgomeryOids.X25519, bytes)
                    XPublic(swiftTry { error -> raw.useNSData { SwiftXdhPublicKey.decodeRawWithRawRepresentation(it, error) } })
                }
                XDH.PublicKey.Format.PEM -> {
                    val der = unwrapPem(PemLabel.PublicKey, bytes)
                    val raw = unwrapSubjectPublicKeyInfo(MontgomeryOids.X25519, der)
                    XPublic(swiftTry { error -> raw.useNSData { SwiftXdhPublicKey.decodeRawWithRawRepresentation(it, error) } })
                }
                else -> error("$format is not supported by CryptoKit XDH")
            }
        }
    }

    override fun privateKeyDecoder(curve: XDH.Curve): KeyDecoder<XDH.PrivateKey.Format, XDH.PrivateKey> {
        check(curve == XDH.Curve.X25519) { "CryptoKit supports X25519 only" }
        return object : KeyDecoder<XDH.PrivateKey.Format, XDH.PrivateKey> {
            override fun decodeFromByteArrayBlocking(format: XDH.PrivateKey.Format, bytes: ByteArray): XDH.PrivateKey = when (format) {
                XDH.PrivateKey.Format.RAW -> XPrivate(
                    swiftTry<SwiftXdhPrivateKey> { error -> bytes.useNSData { SwiftXdhPrivateKey.decodeRawWithRawRepresentation(it, error) } }
                )
                XDH.PrivateKey.Format.DER -> {
                    val raw = unwrapPrivateKeyInfo(MontgomeryOids.X25519, bytes)
                    XPrivate(swiftTry { error -> raw.useNSData { SwiftXdhPrivateKey.decodeRawWithRawRepresentation(it, error) } })
                }
                XDH.PrivateKey.Format.PEM -> {
                    val der = unwrapPem(PemLabel.PrivateKey, bytes)
                    val raw = unwrapPrivateKeyInfo(MontgomeryOids.X25519, der)
                    XPrivate(swiftTry { error -> raw.useNSData { SwiftXdhPrivateKey.decodeRawWithRawRepresentation(it, error) } })
                }
                else -> error("$format is not supported by CryptoKit XDH")
            }
        }
    }

    override fun keyPairGenerator(curve: XDH.Curve): KeyGenerator<XDH.KeyPair> {
        check(curve == XDH.Curve.X25519) { "CryptoKit supports X25519 only" }
        return object : KeyGenerator<XDH.KeyPair> {
            override fun generateKeyBlocking(): XDH.KeyPair {
                val p = SwiftXdhPrivateKey.generate()
                return XKeyPair(XPublic(p.publicKey()), XPrivate(p))
            }
        }
    }

    private class XKeyPair(
        override val publicKey: XDH.PublicKey,
        override val privateKey: XDH.PrivateKey,
    ) : XDH.KeyPair

    private class XPublic(
        val key: SwiftXdhPublicKey,
    ) : XDH.PublicKey, SharedSecretGenerator<XDH.PrivateKey> {
        override fun encodeToByteArrayBlocking(format: XDH.PublicKey.Format): ByteArray = when (format) {
            XDH.PublicKey.Format.RAW -> key.rawRepresentation().toByteArray()
            XDH.PublicKey.Format.DER -> wrapSubjectPublicKeyInfo(
                UnknownKeyAlgorithmIdentifier(MontgomeryOids.X25519),
                key.rawRepresentation().toByteArray()
            )
            XDH.PublicKey.Format.PEM -> wrapPem(
                PemLabel.PublicKey,
                wrapSubjectPublicKeyInfo(
                    UnknownKeyAlgorithmIdentifier(MontgomeryOids.X25519),
                    key.rawRepresentation().toByteArray()
                )
            )
            else -> error("$format is not supported by CryptoKit XDH")
        }
        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PrivateKey> = this
        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PrivateKey): ByteArray {
            require(other is XPrivate)
            return swiftTry { error -> other.key.deriveSecretWith(key, error) }.toByteArray()
        }
    }

    private class XPrivate(
        val key: SwiftXdhPrivateKey,
    ) : XDH.PrivateKey, SharedSecretGenerator<XDH.PublicKey> {
        override fun encodeToByteArrayBlocking(format: XDH.PrivateKey.Format): ByteArray = when (format) {
            XDH.PrivateKey.Format.RAW -> key.rawRepresentation().toByteArray()
            XDH.PrivateKey.Format.DER -> wrapPrivateKeyInfo(
                0,
                UnknownKeyAlgorithmIdentifier(MontgomeryOids.X25519),
                key.rawRepresentation().toByteArray()
            )
            XDH.PrivateKey.Format.PEM -> wrapPem(
                PemLabel.PrivateKey,
                wrapPrivateKeyInfo(
                    0,
                    UnknownKeyAlgorithmIdentifier(MontgomeryOids.X25519),
                    key.rawRepresentation().toByteArray()
                )
            )
            else -> error("$format is not supported by CryptoKit XDH")
        }
        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PublicKey> = this
        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PublicKey): ByteArray {
            require(other is XPublic)
            return swiftTry { error -> key.deriveSecretWith(other.key, error) }.toByteArray()
    }
    }
}
