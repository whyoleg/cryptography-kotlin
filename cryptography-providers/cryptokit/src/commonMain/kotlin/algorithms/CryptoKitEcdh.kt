/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swift.DwcCryptoKitInterop.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.cinterop.*

@OptIn(UnsafeNumber::class)
internal object CryptoKitEcdh : ECDH {
    override fun publicKeyDecoder(curve: EC.Curve): Decoder<EC.PublicKey.Format, ECDH.PublicKey> {
        return PublicKeyDecoder(curve)
    }

    override fun privateKeyDecoder(curve: EC.Curve): Decoder<EC.PrivateKey.Format, ECDH.PrivateKey> {
        return PrivateKeyDecoder(curve)
    }

    override fun keyPairGenerator(curve: EC.Curve): KeyGenerator<ECDH.KeyPair> {
        return KeyPairGenerator(curve)
    }

    private class KeyPairGenerator(
        private val curve: EC.Curve,
    ) : KeyGenerator<ECDH.KeyPair> {
        private val swiftCurve get() = curve.swiftEcCurve()

        override fun generateKeyBlocking(): ECDH.KeyPair {
            val privateKey = DwcEcdhPrivateKey.generateWithCurve(swiftCurve)
            return EcdhKeyPair(
                privateKey = EcdhPrivateKey(curve, privateKey),
                publicKey = EcdhPublicKey(curve, privateKey.publicKey())
            )
        }
    }

    private class PublicKeyDecoder(
        private val curve: EC.Curve,
    ) : Decoder<EC.PublicKey.Format, ECDH.PublicKey> {
        private val swiftCurve get() = curve.swiftEcCurve()

        override fun decodeFromByteArrayBlocking(format: EC.PublicKey.Format, bytes: ByteArray): ECDH.PublicKey {
            return EcdhPublicKey(curve, swiftTry { error ->
                when (format) {
                    EC.PublicKey.Format.JWK            -> {
                        val rawKey = JsonWebKeys.decodeEcPublicKey(curve, curve.orderSize(), bytes)
                        rawKey.useNSData { DwcEcdhPublicKey.decodeRawWithCurve(swiftCurve, it, error) }
                    }
                    EC.PublicKey.Format.RAW            -> bytes.useNSData { DwcEcdhPublicKey.decodeRawWithCurve(swiftCurve, it, error) }
                    EC.PublicKey.Format.RAW.Compressed -> bytes.useNSData {
                        DwcEcdhPublicKey.decodeRawCompressedWithCurve(
                            swiftCurve,
                            it,
                            error
                        )
                    }
                    EC.PublicKey.Format.DER            -> bytes.useNSData { DwcEcdhPublicKey.decodeDerWithCurve(swiftCurve, it, error) }
                    EC.PublicKey.Format.PEM            -> DwcEcdhPublicKey.decodePemWithCurve(swiftCurve, bytes.decodeToString(), error)
                }
            })
        }
    }

    private class PrivateKeyDecoder(
        private val curve: EC.Curve,
    ) : Decoder<EC.PrivateKey.Format, ECDH.PrivateKey> {
        private val swiftCurve get() = curve.swiftEcCurve()

        override fun decodeFromByteArrayBlocking(format: EC.PrivateKey.Format, bytes: ByteArray): ECDH.PrivateKey {
            return EcdhPrivateKey(curve, swiftTry { error ->
                when (format) {
                    EC.PrivateKey.Format.JWK -> {
                        val rawKey = JsonWebKeys.decodeEcPrivateKey(curve, curve.orderSize(), bytes).privateKey
                        rawKey.useNSData { DwcEcdhPrivateKey.decodeRawWithCurve(swiftCurve, it, error) }
                    }
                    EC.PrivateKey.Format.RAW -> bytes.useNSData { DwcEcdhPrivateKey.decodeRawWithCurve(swiftCurve, it, error) }
                    EC.PrivateKey.Format.DER      -> decodeFromDer(bytes, error)
                    EC.PrivateKey.Format.DER.SEC1 -> decodeFromDer(convertEcPrivateKeyFromSec1ToPkcs8(bytes), error)
                    EC.PrivateKey.Format.PEM,
                    EC.PrivateKey.Format.PEM.SEC1,
                                             -> DwcEcdhPrivateKey.decodePemWithCurve(swiftCurve, bytes.decodeToString(), error)
                }
            })
        }

        private fun decodeFromDer(bytes: ByteArray, error: DwcErrorPointer): DwcEcdhPrivateKey? {
            return bytes.useNSData { DwcEcdhPrivateKey.decodeDerWithCurve(swiftCurve, it, error) }
        }
    }
}

private class EcdhKeyPair(
    override val privateKey: ECDH.PrivateKey,
    override val publicKey: ECDH.PublicKey,
) : ECDH.KeyPair

@OptIn(UnsafeNumber::class)
private class EcdhPublicKey(
    private val curve: EC.Curve,
    val publicKey: DwcEcdhPublicKey,
) : ECDH.PublicKey, SharedSecretGenerator<ECDH.PrivateKey> {
    override fun encodeToByteArrayBlocking(format: EC.PublicKey.Format): ByteArray = when (format) {
        EC.PublicKey.Format.JWK -> JsonWebKeys.encodeEcPublicKey(
            curve = curve,
            orderSize = curve.orderSize(),
            publicKey = publicKey.rawRepresentation().toByteArray()
        )
        EC.PublicKey.Format.RAW -> publicKey.rawRepresentation().toByteArray()
        EC.PublicKey.Format.RAW.Compressed -> swiftTry { error -> publicKey.compressedRepresentationAndReturnError(error)?.toByteArray() }
        EC.PublicKey.Format.DER -> publicKey.derRepresentation().toByteArray()
        EC.PublicKey.Format.PEM -> (publicKey.pemRepresentation() + "\n").encodeToByteArray()
    }

    override fun sharedSecretGenerator(): SharedSecretGenerator<ECDH.PrivateKey> = this

    override fun generateSharedSecretToByteArrayBlocking(other: ECDH.PrivateKey): ByteArray {
        require(other is EcdhPrivateKey) { "Can not generate shared secret with private key: ${other::class}" }
        return deriveSecret(other.privateKey, publicKey)
    }
}

@OptIn(UnsafeNumber::class)
private class EcdhPrivateKey(
    private val curve: EC.Curve,
    val privateKey: DwcEcdhPrivateKey,
) : ECDH.PrivateKey, SharedSecretGenerator<ECDH.PublicKey> {
    override fun getPublicKeyBlocking(): ECDH.PublicKey = EcdhPublicKey(curve, privateKey.publicKey())

    override fun encodeToByteArrayBlocking(format: EC.PrivateKey.Format): ByteArray = when (format) {
        EC.PrivateKey.Format.JWK -> JsonWebKeys.encodeEcPrivateKey(
            curve = curve,
            orderSize = curve.orderSize(),
            publicKey = privateKey.publicKey().rawRepresentation().toByteArray(),
            privateKey = privateKey.rawRepresentation().toByteArray()
        )
        EC.PrivateKey.Format.RAW      -> privateKey.rawRepresentation().toByteArray()
        EC.PrivateKey.Format.DER      -> privateKey.derRepresentation().toByteArray()
        EC.PrivateKey.Format.DER.SEC1 -> convertEcPrivateKeyFromPkcs8ToSec1(privateKey.derRepresentation().toByteArray())
        EC.PrivateKey.Format.PEM      -> (privateKey.pemRepresentation() + "\n").encodeToByteArray()
        EC.PrivateKey.Format.PEM.SEC1 -> wrapPem(
            PemLabel.EcPrivateKey,
            convertEcPrivateKeyFromPkcs8ToSec1(privateKey.derRepresentation().toByteArray())
        )
    }

    override fun sharedSecretGenerator(): SharedSecretGenerator<ECDH.PublicKey> = this

    override fun generateSharedSecretToByteArrayBlocking(other: ECDH.PublicKey): ByteArray {
        require(other is EcdhPublicKey) { "Can not generate shared secret with public key: ${other::class}" }
        return deriveSecret(privateKey, other.publicKey)
    }
}

@OptIn(UnsafeNumber::class)
private fun deriveSecret(
    privateKey: DwcEcdhPrivateKey,
    publicKey: DwcEcdhPublicKey,
): ByteArray {
    require(privateKey.curveType() == publicKey.curveType()) { "Can not derive shared secret: different curves" }
    return swiftTry { error ->
        privateKey.deriveSecretWithPublicKey(publicKey, error)
    }.toByteArray()
}

