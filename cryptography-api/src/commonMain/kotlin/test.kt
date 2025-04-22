/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api

import dev.whyoleg.cryptography.api.algorithms.*
import dev.whyoleg.cryptography.api.async.*
import kotlinx.io.bytestring.*

// dev.whyoleg.cryptography.api - sync
// dev.whyoleg.cryptography.algorithms - sync

// dev.whyoleg.cryptography.api.async
// dev.whyoleg.cryptography.algorithms.async

private fun test(provider: CryptographyProvider) {
    val key2 = AesKeyFactory()
        .generate(AesKeyGenerationParameters.B256)
    val cipher = AesGcmCipher(key2)

    val key =
        provider[AesKeyFactory].generate(AesKeyGenerationParameters.B256)

    val ciphertext = key[AesGcmCipher].encryptToBox(
        "".encodeToByteString()
    ).combined
}

private suspend fun test2(crypto: CryptographyProvider) {
    //crypto.(Sha1).hash()

    Sha1().hash("".encodeToByteString())
    AsyncSha1().hash("".encodeToByteString())

    crypto[Sha1].hash("".encodeToByteString())
    crypto[AsyncSha1].hash("".encodeToByteString())

    crypto[Hkdf].deriveSecret(
        "".encodeToByteString(),
        HkdfParameters(
            Sha1,
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
