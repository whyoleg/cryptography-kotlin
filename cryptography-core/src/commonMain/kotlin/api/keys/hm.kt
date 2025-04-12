/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api.keys

import dev.whyoleg.cryptography.api.*
import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlin.jvm.*

public interface CryptographicKey
public interface SymmetricKey : CryptographicKey
public interface AsymmetricKey : CryptographicKey
public interface PublicKey : AsymmetricKey
public interface PrivateKey : AsymmetricKey

// rsa module/package?
public interface RsaKey : AsymmetricKey

public interface RsaPublicKey : RsaKey, PublicKey {
    public fun signatureGenerator(
        // rsaMode: PKCS or PSS
    )

    public fun encryptor(
        // rsaMode: PKCS or RAW or OAEP
    )
}

public interface RsaPrivateKey : RsaKey, PrivateKey

// ecdsa
// sign(EcdsaSignatureFormat.Der, data): BYTES
// sign(data): EcdsaSignature

public interface EcKeyPair {
    public val privateKey: EcPrivateKey
    public val publicKey: EcPublicKey

    public companion object {
        public fun generate(
            curve: EcCurve,
            // capabilities
        ): EcKeyPair = TODO()
    }
}

@JvmInline
public value class EcCurve(public val name: String) {

}

public interface EcKey : AsymmetricKey
public interface EcPublicKey : EcKey, PublicKey {
    public fun verify(
        hashAlgorithm: HashAlgorithm,
        data: ByteString,
        signature: EcdsaSignature,
    )

    public fun tryVerify(
        hashAlgorithm: HashAlgorithm,
        data: ByteString,
        signature: EcdsaSignature,
    ): Boolean

    public fun encodePemToString(): String
    public fun encodePemToByteString(): ByteString
    public fun encodePemToSink(sink: Sink)

    public fun encodeDerToByteString(): ByteString
    public fun encodeDerToSink(sink: Sink)

    public companion object {
        public fun decodePemFromString(text: String): EcPublicKey = TODO()
        public fun decodePemFromByteString(bytes: ByteString): EcPublicKey = TODO()
        public fun decodePemFromSource(source: Source): EcPublicKey = TODO()
    }
}

public interface EcdsaSigner {
    public fun sign(
        hashAlgorithm: HashAlgorithm,
        data: ByteString,
    ): EcdsaSignature
}

public interface EcPrivateKey : EcKey, PrivateKey {
    public fun sign(
        hashAlgorithm: HashAlgorithm,
        data: ByteString,
    ): EcdsaSignature
}

private fun testEC() {
    val keyPair = EcKeyPair.generate(curve)

    val signature = keyPair.privateKey.sign(
        SHA256,
        "some data".encodeToByteString()
    )

    val publicKeyEncoded = keyPair.publicKey.encodeToPem() // String
    val signatureEncoded = signature.encodeToDer()

    val publicKey = EcPublicKey.decodePemFromString(publicKeyEncoded)

    publicKey.verify(
        SHA256,
        "some data".encodeToByteString(),
        EcdsaSignature.decodeDer(signatureEncoded)
    )
}

public class EcdsaSignature private constructor(

) {
    public companion object {
        public fun decodeDer(bytes: ByteString): EcdsaSignature = TODO()
        public fun decodeRaw(bytes: ByteString): EcdsaSignature = TODO()
    }
}

public enum class EcdsaSignatureFormat { Der, Raw }
