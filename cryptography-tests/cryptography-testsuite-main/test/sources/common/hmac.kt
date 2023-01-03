package dev.whyoleg.cryptography.testcase.main

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.random.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.test.*
import kotlin.random.*
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class HmacTest {

    //todo: validate generated key size
    @OptIn(InsecureAlgorithm::class)
    @Test
    fun test() = runTest {
        supportedProviders.forEach { provider ->
            val aesCbc = provider.get(HMAC)

            flow {
                listOf(
                    SHA1,
                    SHA256,
                    SHA384,
                    SHA512,
                ).forEach { digest ->
                    val keyGenerator = aesCbc.keyGenerator(digest)
                    repeat(10) {
                        val key = keyGenerator.generateKey()
                        val encodedKey = key.encodeTo(HMAC.Key.Format.RAW)

                        val signatureGenerator = key.signatureGenerator()
                        repeat(100) {
                            val dataSize = CryptographyRandom.nextInt(10000)
                            val data = CryptographyRandom.nextBytes(dataSize)
                            val signature = signatureGenerator.generateSignature(data)
                            emit(HmacData(digest, encodedKey, data, signature))
                        }
                    }
                }
            }.collect {
                assertTrue(
                    aesCbc
                        .keyDecoder(it.digest)
                        .decodeFrom(HMAC.Key.Format.RAW, it.key)
                        .signatureVerifier()
                        .verifySignature(it.data, it.signature)
                )
            }
        }
    }
}

public class HmacData(
    public val digest: CryptographyAlgorithmId<Digest>,
    public val key: ByteArray,
    public val data: ByteArray,
    public val signature: ByteArray,
)
