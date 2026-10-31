/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlin.test.*

typealias Pbkdf2TestGroupValidator = TestGroupValidator<Pbkdf2TestParameters, SecretDerivationTestDataValidator>

@Serializable
data class Pbkdf2TestParameters(
    val digest: SerializableDigest,
    val salt: SerializableByteString,
    val iterations: Int,
    val outputSizeBytes: Int,
) : TestParameters

// PBKDF2 -> [digest, salt, iterations, output size] -> [secret]
abstract class Pbkdf2AlgorithmTest(cryptographyProvider: CryptographyProvider) : AlgorithmTest<PBKDF2, Pbkdf2TestGroupValidator>(
    provider = cryptographyProvider,
    algorithmId = PBKDF2,
    algorithmLimitation = {
        when {
            provider.isCryptoKit -> fails("PBKDF2 is not supported")
            else                 -> null
        }
    },
) {
    override fun TestValidatorScope.validator(algorithm: PBKDF2): Pbkdf2TestGroupValidator = group<Pbkdf2TestParameters, _>(
        // all providers fail when creating the derivation
        limitation = { parameters ->
            when (parameters.digest) {
                in sha3Digests if provider.isJdkDefault -> fails("PBKDF2 with SHA3 digests is not supported without BouncyCastle")
                else                                    -> failsIfDigestUnsupported(parameters.digest)
            }
        },
    ) { parameters ->
        secrets(
            derivation = algorithm.secretDerivation(parameters),
            secretSize = parameters.outputSizeBytes,
        )
    }

    // https://datatracker.ietf.org/doc/html/rfc6070#section-2
    @Test
    fun rfc6070() = test("rfc6070") {
        group(Pbkdf2TestParameters(SHA1, salt = text("salt"), iterations = 1, outputSizeBytes = 20), "iterations-1") {
            secret(input = text("password"), secret = hex("0c60c80f961f0e71f3a9b524af6012062fe037a6"))
        }
        group(Pbkdf2TestParameters(SHA1, salt = text("salt"), iterations = 2, outputSizeBytes = 20), "iterations-2") {
            secret(input = text("password"), secret = hex("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"))
        }
        group(Pbkdf2TestParameters(SHA1, salt = text("salt"), iterations = 4096, outputSizeBytes = 20), "iterations-4096") {
            secret(input = text("password"), secret = hex("4b007901b765489abead49d926f721d065a429c1"))
        }
        group(
            Pbkdf2TestParameters(SHA1, salt = text("salt"), iterations = 16777216, outputSizeBytes = 20),
            "iterations-16777216",
            skip = "16777216 iterations are too slow",
        ) {
            secret(input = text("password"), secret = hex("eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"))
        }
        group(
            Pbkdf2TestParameters(SHA1, salt = text("saltSALTsaltSALTsaltSALTsaltSALTsalt"), iterations = 4096, outputSizeBytes = 25),
            "long-input",
        ) {
            secret(input = text("passwordPASSWORDpassword"), secret = hex("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"))
        }
        group(Pbkdf2TestParameters(SHA1, salt = text("sa\u0000lt"), iterations = 4096, outputSizeBytes = 16), "zero-byte") {
            secret(input = text("pass\u0000word"), secret = hex("56fa6aa75548099dcc37d7f03425e0c3"))
        }
    }

    @Test
    fun random() = test("random") { algorithm ->
        listOf(SHA1, SHA256, SHA512, SHA3_256).forEach { digest ->
            listOf(
                Pbkdf2TestParameters(digest, randomBytes(16), iterations = 1, outputSizeBytes = digest.digestSize),
                Pbkdf2TestParameters(digest, randomBytes(1), iterations = 1000, outputSizeBytes = 1),
                Pbkdf2TestParameters(
                    digest,
                    randomBytes(100),
                    iterations = 1 + CryptographyRandom.nextInt(2000),
                    outputSizeBytes = 1 + CryptographyRandom.nextInt(200)
                ),
            ).forEach { parameters ->
                group(parameters) {
                    // empty password is equal to password with a single zero byte, as HMAC pads the key with zeros;
                    // JDK requires password to be a valid UTF-8 string
                    generateSecretsFor(
                        derivation = algorithm.secretDerivation(parameters),
                        inputs = listOf(1, 32, 1000).map { ByteString(randomString(it).encodeToByteArray()) },
                    )
                }
            }
        }
    }
}

private fun PBKDF2.secretDerivation(parameters: Pbkdf2TestParameters): SecretDerivation =
    secretDerivation(parameters.digest, parameters.iterations, parameters.outputSizeBytes.bytes, parameters.salt)

private fun randomString(size: Int): String {
    val chars = ('a'..'z') + ('A'..'Z') + ('0'..'9')
    return CharArray(size) { chars[CryptographyRandom.nextInt(chars.size)] }.concatToString()
}
