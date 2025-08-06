/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:OptIn(
    ExperimentalTime::class, // for kotlin.time.Instant
    DelicateJoseApi::class // for crypto operations
)

package dev.whyoleg.cryptography.serialization.jose

import dev.whyoleg.cryptography.bigint.*
import kotlinx.serialization.*
import kotlinx.serialization.json.*
import kotlin.coroutines.*
import kotlin.random.*
import kotlin.time.*
import kotlin.time.Duration.Companion.days

private fun cryptoSign(headers: JwsHeaders, signingInput: ByteArray): ByteArray {
    if (headers.combined.algorithm != JwsAlgorithm.ES256) error("???")

    TODO("signing impl")
}

private fun cryptoVerify(headers: JwsHeaders, signingInput: ByteArray, signature: ByteArray): Boolean {
    when (headers.combined.algorithm) {
        JwsAlgorithm.HS256, JwsAlgorithm.HS384, JwsAlgorithm.HS512 -> TODO("verify impl")
        else                                                       -> error("???")
    }
}

private fun createToken() {
    val claims = JwtClaims {
        issuer = "me"
        subject = "myself"
        audience = "you"
        expirationTime = Clock.System.now() + 1.days
    }
    val header = JwsHeader {
        algorithm = JwsAlgorithm.ES256
        type = "JWT"
    }
    val payload = Json.JoseCompliant.encodeToString(claims).encodeToByteArray()

    val jwt = JwsContent(header, payload).sign(::cryptoSign).toCompactString()

    //

    val content = JwsObject.parseCompactString(jwt).verify(::cryptoVerify)

    val decodedClaims = Json.JoseCompliant.decodeFromString<JwtClaims>(content.payload.decodeToString())

    println(decodedClaims.expirationTime)
}

@Serializable
private class WalletClaims(
    val walletName: String,
    val walletAddress: String,
)

private fun customClaims() {
    val claims = JwtClaims {
        encode(
            WalletClaims(
                walletName = "My Wallet",
                walletAddress = "0x1234567890123456789012345678901234567890",
            )
        )
    }

    println(claims.decode<WalletClaims>().walletAddress)
}

private fun key() {
    JwkObject(
        parameters = JwkParameters.RSA(
            modulus = "123".toBigInt(),
            exponent = "123".toBigInt(),
            null
        ),
        keyId = "test-key-id",
        publicKeyUse = JwkPublicKeyUse.Signature,
        keyOperations = listOf(
            JwkOperation.Sign
        ),
        algorithm = JwsAlgorithm.RS256,
    )
}

private suspend fun suspendEncrypt() {
    val content = JweContent(
        sharedHeaders = JweHeaders {
            protected.algorithm = JweAlgorithm.RSA_OAEP_256
            unprotected.contentType = "text/plain"
        },
        recipientHeaders = listOf(
            JweHeader { keyId = "1" },
            JweHeader { keyId = "2" }
        ),
        payload = "Hello world!".encodeToByteArray()
    )

    val obj = content.encrypt(
        mode = JweEncryptingMode.ALL,
        keyGenerator = { headers ->
            Random.nextBytes(100)
        },
        keyEncryptor = { headers, key ->
            suspendCoroutine {
                // call remote api
            }
        },
        contentEncryptor = { headers, cek, plaintext, authenticatedData ->
            JweCiphertext(
                iv = Random.nextBytes(16),
                ciphertext = Random.nextBytes(100),
                authenticationTag = Random.nextBytes(16)
            )
        }
    )

    println(obj.ciphertext)

    val json = obj.toJsonString()

    val decryptedContent = JweObject.parseJsonString(json).also {
        require(it.recipients.size == 2)
        require(it.sharedHeaders.protected.algorithm == JweAlgorithm.RSA_OAEP_256)
    }.decrypt(
        mode = JweEncryptingMode.AT_LEAST_ONCE,
        keyDecryptor = { headers, key ->
            if (headers.combined.keyId == "1") key else null // null -> can't decrypt
        },
        contentDecryptor = { headers, cek, ciphertext, authenticationTag ->
            TODO("decrypt")
        }
    )

    println(decryptedContent.payload.decodeToString() == "Hello world!")
}