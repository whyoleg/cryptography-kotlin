package dev.whyoleg.cryptography.testcase.main

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.random.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.test.*
import kotlin.random.*
import kotlin.test.*

interface TestParams
interface TestData
interface TestSuite<A : CryptographyAlgorithm, P : TestParams, T : TestData> {
    suspend fun produce(algorithm: A, params: P): T
    suspend fun verify(algorithm: A, data: T)
}

class AesCbcTestParams(
    val keySize: SymmetricKeySize,
    val padding: Boolean,
    val plaintext: ByteArray,
) : TestParams

class AesCbcTestData(
    val padding: Boolean,
    val key: ByteArray,
    val plaintext: ByteArray,
    val ciphertext: ByteArray,
) : TestData

object AesCbcTestSuite : TestSuite<AES.CBC, AesCbcTestParams, AesCbcTestData> {
    override suspend fun produce(algorithm: AES.CBC, params: AesCbcTestParams): AesCbcTestData {
        val key = algorithm
            .keyGenerator(params.keySize)
            .generateKey()

        val encodedKey = key
            .encodeTo(AES.Key.Format.RAW)

        assertEquals(params.keySize.value.bytes, encodedKey.size)

        val ciphertext = key
            .cipher(params.padding)
            .encrypt(params.plaintext)

        return AesCbcTestData(params.padding, encodedKey, params.plaintext, ciphertext)
    }

    override suspend fun verify(algorithm: AES.CBC, data: AesCbcTestData) {
        val plaintext = algorithm
            .keyDecoder()
            .decodeFrom(AES.Key.Format.RAW, data.key)
            .cipher(data.padding)
            .decrypt(data.ciphertext)
        assertContentEquals(data.plaintext, plaintext)
    }
}

//main
// - generate data
// - verify data (locally) (verify)
// - send data (to remote) (verify)

//cross
// - receive data (from remote)
// - verify data (from remote) (verify)

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

                            emit(AesCbcTestData(true, encodedKey, plaintext, ciphertext))
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
