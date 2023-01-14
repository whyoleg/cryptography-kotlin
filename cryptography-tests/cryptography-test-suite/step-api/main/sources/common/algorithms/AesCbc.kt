package dev.whyoleg.cryptography.test.step.api.algorithms

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.api.*
import dev.whyoleg.cryptography.test.step.api.*
import dev.whyoleg.cryptography.test.step.api.generators.*

private const val keyIterations = 10
private const val cipherIterations = 10
private const val maxPlaintextSize = 10000
private const val blockSize = 16 //for padding

private val CryptographyProvider.supportsNoPadding get() = !isWebCrypto

// WebCrypto doesn't support 192bits - TODO: WHY???
private val CryptographyProvider.supports192BitKey get() = !isWebCrypto

private inline fun paddings(block: (padding: Boolean, paddingParams: String) -> Unit) {
    block(false, "NoPadding")
    block(true, "PKCS7Padding")
}

private val generate = TestRun { api, provider ->
    val algorithm = provider.get(AES.CBC)
    symmetricKeySizes { keySize, keyParams ->
        if (keySize == SymmetricKeySize.B192 && !provider.supports192BitKey) {
            println("skip: 192bit key is not supported by ${provider.name}")
            return@symmetricKeySizes
        }

        val keyGenerator = algorithm.keyGenerator(keySize)
        repeat(keyIterations) {
            val key = keyGenerator.generateKey()
            val keyId = api.keys.save(
                algorithm = algorithm.id.name,
                params = keyParams,
                data = EncodedKey {
                    put(StringKeyFormat.RAW, key.encodeTo(AES.Key.Format.RAW))
                    if (provider.supportsJwk) put(StringKeyFormat.JWK, key.encodeTo(AES.Key.Format.JWK))
                }
            )
            paddings { padding, paddingParams ->
                if (!padding && !provider.supportsNoPadding) {
                    println("skip: NoPadding is not supported by $provider")
                    return@paddings
                }

                val cipher = key.cipher(padding)
                repeat(cipherIterations) { //TODO: if padding, need to generate data with length % 16 == 0
                    val plaintextSize = CryptographyRandom.nextInt(maxPlaintextSize).let {
                        if (padding) it else (it + blockSize - it % blockSize)
                    }
                    println("generate: plaintext.size  = $plaintextSize")
                    val plaintext = CryptographyRandom.nextBytes(plaintextSize)
                    val ciphertext = cipher.encrypt(plaintext)
                    println("generate: ciphertext.size = ${ciphertext.size}")

                    //only simple check here to fail fast
                    cipher.decrypt(ciphertext).assertContentEquals(plaintext)

                    api.ciphers.save(
                        algorithm = algorithm.id.name,
                        params = paddingParams,
                        data = CipherData(keyId, plaintext, ciphertext),
                        metadata = mapOf("key.params" to keyParams)
                    )
                }
            }
        }
    }
}

private val validate = TestRun { api, provider ->
    val algorithm = provider.get(AES.CBC)
    val keyDecoder = algorithm.keyDecoder()

    paddings { padding, paddingParams ->
        if (!padding && !provider.supportsNoPadding) return@paddings

        api.ciphers.getAll(
            algorithm = algorithm.id.name,
            params = paddingParams,
        ).forEach { (metadata, encodedCipher) ->
            if (metadata["key.params"]!! == "192bits" && !provider.supports192BitKey) return@forEach //TODO

            val encodedKey = api.keys.get(
                algorithm = algorithm.id.name,
                params = metadata["key.params"]!!,
                id = encodedCipher.keyId
            ).data
            encodedKey.formats.forEach { (stringFormat, data) ->
                val key = keyDecoder.decodeFrom(
                    format = when (stringFormat) {
                        StringKeyFormat.RAW -> AES.Key.Format.RAW
                        StringKeyFormat.JWK -> AES.Key.Format.JWK.takeIf { provider.supportsJwk }
                        else                -> error("Unsupported key format: $stringFormat") //TODO
                    },
                    input = data
                ) ?: return@forEach

                encodedKey.formats[StringKeyFormat.RAW]?.let { bytes ->
                    key.encodeTo(AES.Key.Format.RAW).assertContentEquals(bytes)
                }
                //TODO: JWK should be checked by JSON equality, and not per bytes (use kx.serialization)

                key.cipher(padding).run {
                    decrypt(encodedCipher.ciphertext).assertContentEquals(encodedCipher.plaintext)
                    decrypt(encrypt(encodedCipher.plaintext)).assertContentEquals(encodedCipher.plaintext)
                }
            }
        }
    }
}

internal val aesCbc = "AES-CBC".testAlgorithm(
    generate = generate,
    validate = validate,
)
