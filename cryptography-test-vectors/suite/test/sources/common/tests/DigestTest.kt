package dev.whyoleg.cryptography.test.vectors.suite.tests

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.support.*
import dev.whyoleg.cryptography.test.vectors.suite.*
import dev.whyoleg.cryptography.test.vectors.suite.api.*

private const val iterations = 100
private const val maxDataSize = 10000

class Sha1Test : DigestTest(SHA1)
class Sha256Test : DigestTest(SHA256)
class Sha384Test : DigestTest(SHA384)
class Sha512Test : DigestTest(SHA512)

abstract class DigestTest(algorithmId: CryptographyAlgorithmId<Digest>) : TestVectorTest<Digest>(algorithmId) {
    override suspend fun generate(logging: TestLoggingContext, api: TestVectorApi, provider: CryptographyProvider, algorithm: Digest) {
        val hasher = algorithm.hasher()
        val parametersId = api.digests.saveParameters(TestVectorParameters.Empty)
        repeat(iterations) {
            val dataSize = CryptographyRandom.nextInt(maxDataSize)
            logging.log("data.size  = $dataSize")
            val data = CryptographyRandom.nextBytes(dataSize)
            val digest = hasher.hash(data)
            logging.log("digest.size  = ${digest.size}")
            hasher.hash(data).assertContentEquals(digest)

            api.digests.saveData(parametersId, DigestData(data, digest))
        }
    }

    override suspend fun validate(logging: TestLoggingContext, api: TestVectorApi, provider: CryptographyProvider, algorithm: Digest) {
        val hasher = algorithm.hasher()

        api.digests.getParameters<TestVectorParameters.Empty> { _, parametersId ->
            api.digests.getData<DigestData>(parametersId) { data, _ ->
                hasher.hash(data.data).assertContentEquals(data.digest)
            }
        }
    }
}
