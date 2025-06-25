/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swiftinterop.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.cinterop.*

@OptIn(UnsafeNumber::class)
internal object CryptoKitEcdh : ECDH {
    override fun publicKeyDecoder(curve: EC.Curve): KeyDecoder<EC.PublicKey.Format, ECDH.PublicKey> {
        return PublicKeyDecoder(curve.swiftEcCurve())
    }

    override fun privateKeyDecoder(curve: EC.Curve): KeyDecoder<EC.PrivateKey.Format, ECDH.PrivateKey> {
        return PrivateKeyDecoder(curve.swiftEcCurve())
    }

    override fun keyPairGenerator(curve: EC.Curve): KeyGenerator<ECDH.KeyPair> {
        return KeyPairGenerator(curve.swiftEcCurve())
    }

    private class KeyPairGenerator(
        private val curve: SwiftEcCurve,
    ) : KeyGenerator<ECDH.KeyPair> {
        override fun generateKeyBlocking(): ECDH.KeyPair {
            val privateKey = SwiftEcdhPrivateKey.generateWithCurve(curve)
            return EcdhKeyPair(
                privateKey = EcdhPrivateKey(privateKey),
                publicKey = EcdhPublicKey(privateKey.publicKey())
            )
        }
    }

    private class PublicKeyDecoder(
        private val curve: SwiftEcCurve,
    ) : KeyDecoder<EC.PublicKey.Format, ECDH.PublicKey> {
        override fun decodeFromByteArrayBlocking(format: EC.PublicKey.Format, bytes: ByteArray): ECDH.PublicKey {
            return EcdhPublicKey(swiftTry { error ->
                when (format) {
                    EC.PublicKey.Format.JWK -> error("JWK is not supported")
                    EC.PublicKey.Format.RAW -> bytes.useNSData { SwiftEcdhPublicKey.decodeRawWithCurve(curve, it, error) }
                    EC.PublicKey.Format.RAW.Compressed -> bytes.useNSData { SwiftEcdhPublicKey.decodeRawCompressedWithCurve(curve, it, error) }
                    EC.PublicKey.Format.DER -> bytes.useNSData { SwiftEcdhPublicKey.decodeDerWithCurve(curve, it, error) }
                    EC.PublicKey.Format.PEM -> SwiftEcdhPublicKey.decodePemWithCurve(curve, bytes.decodeToString(), error)
                }
            })
        }
    }

    private class PrivateKeyDecoder(
        private val curve: SwiftEcCurve,
    ) : KeyDecoder<EC.PrivateKey.Format, ECDH.PrivateKey> {
        override fun decodeFromByteArrayBlocking(format: EC.PrivateKey.Format, bytes: ByteArray): ECDH.PrivateKey {
            return EcdhPrivateKey(swiftTry { error ->
                when (format) {
                    EC.PrivateKey.Format.JWK      -> error("JWK is not supported")
                    EC.PrivateKey.Format.RAW      -> bytes.useNSData { SwiftEcdhPrivateKey.decodeRawWithCurve(curve, it, error) }
                    EC.PrivateKey.Format.DER      -> decodeFromDer(bytes, error)
                    EC.PrivateKey.Format.DER.SEC1 -> decodeFromDer(convertEcPrivateKeyFromSec1ToPkcs8(bytes), error)
                    EC.PrivateKey.Format.PEM,
                    EC.PrivateKey.Format.PEM.SEC1,
                                                  -> SwiftEcdhPrivateKey.decodePemWithCurve(curve, bytes.decodeToString(), error)
                }
            })
        }

        private fun decodeFromDer(bytes: ByteArray, error: SwiftErrorPointer): SwiftEcdhPrivateKey? {
            return bytes.useNSData { SwiftEcdhPrivateKey.decodeDerWithCurve(curve, it, error) }
        }
    }
}

private class EcdhKeyPair(
    override val privateKey: ECDH.PrivateKey,
    override val publicKey: ECDH.PublicKey,
) : ECDH.KeyPair

@OptIn(UnsafeNumber::class)
private class EcdhPublicKey(
    val publicKey: SwiftEcdhPublicKey,
) : ECDH.PublicKey, SharedSecretGenerator<ECDH.PrivateKey> {
    override fun encodeToByteArrayBlocking(format: EC.PublicKey.Format): ByteArray = when (format) {
        EC.PublicKey.Format.JWK -> error("JWK is not supported")
        EC.PublicKey.Format.RAW -> publicKey.rawRepresentation().toByteArray()
        EC.PublicKey.Format.RAW.Compressed -> publicKey.compressedRepresentation().toByteArray()
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
    val privateKey: SwiftEcdhPrivateKey,
) : ECDH.PrivateKey, SharedSecretGenerator<ECDH.PublicKey> {
    override fun encodeToByteArrayBlocking(format: EC.PrivateKey.Format): ByteArray = when (format) {
        EC.PrivateKey.Format.JWK      -> error("JWK is not supported")
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
    privateKey: SwiftEcdhPrivateKey,
    publicKey: SwiftEcdhPublicKey,
): ByteArray {
    require(privateKey.curveType() == publicKey.curveType()) { "Can not derive shared secret: different curves" }
    return swiftTry { error ->
        privateKey.deriveSecretWithPublicKey(publicKey, error)
    }.toByteArray()
}
