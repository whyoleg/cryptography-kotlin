/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api

import dev.whyoleg.cryptography.api.algorithms.*
import dev.whyoleg.cryptography.api.async.*
import kotlinx.io.bytestring.*

// crypto.api
// crypto.[core|async] - depends on [core|async] primitives/algorithms

// crypto.primitives - public/secret keys
// crypto.primitives.[core|async] - hash/sign/key/etc

// crypto.algorithms - AesKey, ...?
// crypto.algorithms.[core|async] - aes, ec, hpkf, hpke


private fun testEc(provider: CryptographyProvider) {
    val keyPair = EcKeyPairGenerator().generate(
        EcKeyPairGeneratorParameters(
            EcCurve.P256
        )
    )

    EcPublicKeyFactory()
        .decodeFromPem("")

    keyPair
        .publicKey
        .encodeToPemString()
}

private fun test(provider: CryptographyProvider) {
    val key2 = AesKeyFactory()
        .generate(AesKeyGenerationParameters.B256)
    val cipher = AesGcmCipher(key2)

    val key =
        provider[AesKeyFactory].generate(AesKeyGenerationParameters.B256)

    val ciphertext = key[AesGcmCipher].encryptToBox(
        "".encodeToByteString()
    ).combined






    CryptographyProvider.Default.get(Sha1).hash("".encodeToByteString())
}

private suspend fun test2(crypto: CryptographyProvider) {
    //crypto.(Sha1).hash()

    Sha1().hash("".encodeToByteString())
    Sha1.Async().hash("".encodeToByteString())
    Sha1Digest().hash("".encodeToByteString())
    Sha1Digest.Async().hash("".encodeToByteString())

    crypto[Sha1].hash("".encodeToByteString())
    crypto[Sha1.Async].hash("".encodeToByteString())
    crypto[Sha1Digest].hash("".encodeToByteString())
    crypto[Sha1Digest.Async].hash("".encodeToByteString())

    crypto[Hkdf].deriveSecret(
        "".encodeToByteString(),
        HkdfParameters(
            Sha1Digest,
            10,
            ByteString()
        )
    )
    crypto[Hkdf].deriveSecret(
        "".encodeToByteString(),
        HkdfParameters(
            Sha1Digest,
            10,
            ByteString()
        )
    )

    Hkdf().deriveSecret(
        "".encodeToByteString(),
        HkdfParameters(
            Sha1Digest,
            10,
            ByteString()
        )
    )
}

internal fun hkdf(
    input: ByteString,
    // parameters
    digest: CryptographyProvider.Tag<SimpleDigest>,
    outputSize: Int,
    salt: ByteString,
    info: ByteString? = null,
): ByteString {
    val parameters = HkdfParameters(digest, outputSize, salt, info)
    return Hkdf().deriveSecret(input, parameters)
}

internal fun hkdf(
    input: ByteString,
    // parameters
    digest: CryptographyProvider.Tag<SimpleDigest>,
    outputSize: Int,
    salt: ByteString,
    info: ByteString? = null,
): ByteString {
    val parameters = HkdfParameters(digest, outputSize, salt, info)
    return Hkdf(parameters).deriveSecret(input, Unit)
}
