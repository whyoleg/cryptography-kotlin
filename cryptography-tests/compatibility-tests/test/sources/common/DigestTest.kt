package dev.whyoleg.cryptography.tests.compatibility

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.tests.compatibility.api.*
import kotlin.test.*

private const val iterations = 100
private const val maxDataSize = 10000

class Sha1Test : DigestTest(SHA1)
class Sha256Test : DigestTest(SHA256)
class Sha384Test : DigestTest(SHA384)
class Sha512Test : DigestTest(SHA512)

abstract class DigestTest(algorithmId: CryptographyAlgorithmId<Digest>) : CompatibilityTest<Digest>(algorithmId) {
    override suspend fun CompatibilityTestContext<Digest>.generate() {
        val hasher = algorithm.hasher()
        val parametersId = api.digests.saveParameters(TestParameters.Empty)
        repeat(iterations) {
            val dataSize = CryptographyRandom.nextInt(maxDataSize)
            logger.log("data.size   = $dataSize")
            val data = CryptographyRandom.nextBytes(dataSize)
            val digest = hasher.hash(data)
            logger.log("digest.size = ${digest.size}")

            assertContentEquals(digest, hasher.hash(data), "Initial Hash")

            api.digests.saveData(parametersId, DigestData(data, digest))
        }
    }

    override suspend fun CompatibilityTestContext<Digest>.validate() {
        val hasher = algorithm.hasher()

        api.digests.getParameters<TestParameters.Empty> { _, parametersId ->
            api.digests.getData<DigestData>(parametersId) { (data, digest), _ ->
                assertContentEquals(digest, hasher.hash(data), "Hash")
            }
        }
    }
}
