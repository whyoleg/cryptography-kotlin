/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.providers.tests.support.*
import dev.whyoleg.cryptography.random.*
import kotlin.test.*

private const val iterations = 100
private const val maxDataSize = 10000

class Md5Test : DigestTest(MD5)
class Sha1Test : DigestTest(SHA1)

class Sha224Test : DigestTest(SHA224)
class Sha256Test : DigestTest(SHA256)
class Sha384Test : DigestTest(SHA384)
class Sha512Test : DigestTest(SHA512)

class Sha3b224Test : DigestTest(SHA3_224)
class Sha3b256Test : DigestTest(SHA3_256)
class Sha3b384Test : DigestTest(SHA3_384)
class Sha3b512Test : DigestTest(SHA3_512)

abstract class DigestTest(algorithmId: CryptographyAlgorithmId<Digest>) : CompatibilityTest<Digest>(algorithmId) {
    override suspend fun CompatibilityTestScope<Digest>.generate() {
        if (!supportsDigest(algorithmId)) return

        val hasher = algorithm.hasher()
        val parametersId = api.digests.saveParameters(TestParameters.Empty)
        repeat(iterations) {
            val dataSize = CryptographyRandom.nextInt(maxDataSize)
            logger.log { "data.size   = $dataSize" }
            val data = CryptographyRandom.nextBytes(dataSize)
            val digest = hasher.hash(data)
            logger.log { "digest.size = ${digest.size}" }

            assertContentEquals(digest, hasher.hash(data), "Initial Hash")

            api.digests.saveData(parametersId, DigestData(data, digest))
        }
    }

    override suspend fun CompatibilityTestScope<Digest>.validate() {
        if (!supportsDigest(algorithmId)) return
        val hasher = algorithm.hasher()

        api.digests.getParameters<TestParameters.Empty> { _, parametersId, _ ->
            api.digests.getData<DigestData>(parametersId) { (data, digest), _, _ ->
                assertContentEquals(digest, hasher.hash(data), "Hash")
            }
        }
    }
}
