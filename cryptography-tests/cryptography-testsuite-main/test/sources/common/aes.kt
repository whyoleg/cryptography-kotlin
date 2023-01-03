package dev.whyoleg.cryptography.testcase.main

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.random.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.test.*
import kotlin.random.*
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class AesCbcTest {

    @Test
    fun test() = runTest {
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
                        val encodedKey = key.encodeTo(AES.Key.Format.RAW)

                        val cipher = key.cipher(true)
                        repeat(100) {
                            val plaintextSize = CryptographyRandom.nextInt(10000)
                            val plaintext = CryptographyRandom.nextBytes(plaintextSize)
                            val ciphertext = cipher.encrypt(plaintext)

                            emit(AesCbcData(true, encodedKey, plaintext, ciphertext))
                        }
                    }
                }
            }.collect {
                if (!it.padding && provider.isWebCrypto) return@collect
                val plaintext = aesCbc
                    .keyDecoder()
                    .decodeFrom(AES.Key.Format.RAW, it.key)
                    .cipher(it.padding)
                    .decrypt(it.ciphertext)
                assertContentEquals(it.plaintext, plaintext)
            }
        }
    }
}

public class AesCbcData(
    public val padding: Boolean,
    public val key: ByteArray,
    public val plaintext: ByteArray,
    public val ciphertext: ByteArray,
)
