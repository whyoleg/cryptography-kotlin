package dev.whyoleg.cryptography.testcase.main

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.random.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.test.*
import kotlin.random.*
import kotlin.test.*

class AesCbcTestData(
    val padding: Boolean,
    val rawKey: Buffer,
    val jwkKey: Buffer?,
    val plaintext: Buffer,
    val ciphertext: Buffer,
)

//main
// - generate data
// - verify data (locally) (verify)
// - send data (to remote) (verify)

//cross
// - receive data (from remote)
// - verify data (from remote) (verify)

@OptIn(ExperimentalCoroutinesApi::class)
class AesCbcTest {

    //3 key sizes -> 30 keys (10 per key size) -> 60 encoded keys (2 per key)
    //                                         -> 3000 plaintexts/ciphertexts (100 per key) (x2 if padding/no padding)

    @Test
    fun testCipher() = runTest {
        supportedProviders.forEach { provider ->
            val aesCbc = provider.get(AES.CBC)

            flow {
                listOf(
                    SymmetricKeySize.B128,
                    SymmetricKeySize.B192,
                    SymmetricKeySize.B256
                ).filter {
                    //TODO
                    if (provider.isWebCrypto) it != SymmetricKeySize.B192 else true
                }.forEach { keySize ->
                    val keyGenerator = aesCbc.keyGenerator(keySize)
                    repeat(10) {
                        val key = keyGenerator.generateKey()
                        val cipher = key.cipher(true)
                        repeat(10) {
                            val plaintextSize = CryptographyRandom.nextInt(10000)
                            val plaintext = CryptographyRandom.nextBytes(plaintextSize)
                            val ciphertext = cipher.encrypt(plaintext)

                            cipher.decrypt(ciphertext).assertContentEquals(plaintext)

                            emit(
                                AesCbcTestData(
                                    padding = true,
                                    rawKey = key.encodeTo(AES.Key.Format.RAW),
                                    jwkKey = key.encodeToIf(provider.isWebCrypto, AES.Key.Format.JWK),
                                    plaintext = plaintext,
                                    ciphertext = ciphertext
                                )
                            )
                        }
                    }
                }
            }.collect {
                if (!it.padding && provider.isWebCrypto) return@collect

                val keyDecoder = aesCbc.keyDecoder()

                listOfNotNull(
                    keyDecoder.decodeFrom(AES.Key.Format.RAW, it.rawKey),
                    it.jwkKey?.let { keyDecoder.decodeFromIf(provider.isWebCrypto, AES.Key.Format.JWK, it) }
                ).forEach { key ->
                    key.encodeTo(AES.Key.Format.RAW).assertContentEquals(it.rawKey)
                    it.jwkKey?.let { key.encodeTo(AES.Key.Format.JWK).assertContentEquals(it) }

                    key.cipher(it.padding).run {
                        decrypt(it.ciphertext).assertContentEquals(it.plaintext)
                        decrypt(encrypt(it.plaintext)).assertContentEquals(it.plaintext)
                    }
                }
            }
        }
    }
}
