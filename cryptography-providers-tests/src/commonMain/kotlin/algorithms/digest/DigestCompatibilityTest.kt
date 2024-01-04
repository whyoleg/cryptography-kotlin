/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.algorithms.digest

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.providers.tests.api.compatibility.*
import dev.whyoleg.cryptography.random.*
import kotlin.test.*

private const val iterations = 100
private const val maxDataSize = 10000

abstract class Md5CompatibilityTest(provider: CryptographyProvider) : DigestCompatibilityTest(MD5, provider)
abstract class Sha1CompatibilityTest(provider: CryptographyProvider) : DigestCompatibilityTest(SHA1, provider)

abstract class Sha224CompatibilityTest(provider: CryptographyProvider) : DigestCompatibilityTest(SHA224, provider)
abstract class Sha256CompatibilityTest(provider: CryptographyProvider) : DigestCompatibilityTest(SHA256, provider)
abstract class Sha384CompatibilityTest(provider: CryptographyProvider) : DigestCompatibilityTest(SHA384, provider)
abstract class Sha512CompatibilityTest(provider: CryptographyProvider) : DigestCompatibilityTest(SHA512, provider)

abstract class Sha3B224CompatibilityTest(provider: CryptographyProvider) : DigestCompatibilityTest(SHA3_224, provider)
abstract class Sha3B256CompatibilityTest(provider: CryptographyProvider) : DigestCompatibilityTest(SHA3_256, provider)
abstract class Sha3B384CompatibilityTest(provider: CryptographyProvider) : DigestCompatibilityTest(SHA3_384, provider)
abstract class Sha3B512CompatibilityTest(provider: CryptographyProvider) : DigestCompatibilityTest(SHA3_512, provider)

abstract class DigestCompatibilityTest(algorithmId: CryptographyAlgorithmId<Digest>, provider: CryptographyProvider) :
    CompatibilityTest<Digest>(algorithmId, provider) {
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
