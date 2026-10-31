/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*
import kotlin.math.*
import kotlin.test.*

abstract class Md5AlgorithmTest(cryptographyProvider: CryptographyProvider) : DigestAlgorithmTest(
    provider = cryptographyProvider,
    algorithmId = MD5,
    digestSize = 16,
    abcDigestHex = "900150983cd24fb0d6963f7d28e17f72",
)

abstract class Sha1AlgorithmTest(cryptographyProvider: CryptographyProvider) : DigestAlgorithmTest(
    provider = cryptographyProvider,
    algorithmId = SHA1,
    digestSize = 20,
    abcDigestHex = "a9993e364706816aba3e25717850c26c9cd0d89d",
)

abstract class Sha224AlgorithmTest(cryptographyProvider: CryptographyProvider) : DigestAlgorithmTest(
    provider = cryptographyProvider,
    algorithmId = SHA224,
    digestSize = 28,
    abcDigestHex = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
)

abstract class Sha256AlgorithmTest(cryptographyProvider: CryptographyProvider) : DigestAlgorithmTest(
    provider = cryptographyProvider,
    algorithmId = SHA256,
    digestSize = 32,
    abcDigestHex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
)

abstract class Sha384AlgorithmTest(cryptographyProvider: CryptographyProvider) : DigestAlgorithmTest(
    provider = cryptographyProvider,
    algorithmId = SHA384,
    digestSize = 48,
    abcDigestHex = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
)

abstract class Sha512AlgorithmTest(cryptographyProvider: CryptographyProvider) : DigestAlgorithmTest(
    provider = cryptographyProvider,
    algorithmId = SHA512,
    digestSize = 64,
    abcDigestHex = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
)

abstract class Sha3B224AlgorithmTest(cryptographyProvider: CryptographyProvider) : DigestAlgorithmTest(
    provider = cryptographyProvider,
    algorithmId = SHA3_224,
    digestSize = 28,
    abcDigestHex = "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
)

abstract class Sha3B256AlgorithmTest(cryptographyProvider: CryptographyProvider) : DigestAlgorithmTest(
    provider = cryptographyProvider,
    algorithmId = SHA3_256,
    digestSize = 32,
    abcDigestHex = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
)

abstract class Sha3B384AlgorithmTest(cryptographyProvider: CryptographyProvider) : DigestAlgorithmTest(
    provider = cryptographyProvider,
    algorithmId = SHA3_384,
    digestSize = 48,
    abcDigestHex = "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
)

abstract class Sha3B512AlgorithmTest(cryptographyProvider: CryptographyProvider) : DigestAlgorithmTest(
    provider = cryptographyProvider,
    algorithmId = SHA3_512,
    digestSize = 64,
    abcDigestHex = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
)

abstract class Ripemd160AlgorithmTest(cryptographyProvider: CryptographyProvider) : DigestAlgorithmTest(
    provider = cryptographyProvider,
    algorithmId = RIPEMD160,
    digestSize = 20,
    abcDigestHex = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
)

// Digest -> [digest]
abstract class DigestAlgorithmTest(
    provider: CryptographyProvider,
    algorithmId: CryptographyAlgorithmId<Digest>,
    private val digestSize: Int,
    // digest of "abc"
    private val abcDigestHex: String,
) : AlgorithmTest<Digest, DigestTestDataValidator>(
    provider = provider,
    algorithmId = algorithmId,
    algorithmLimitation = { failsIfDigestUnsupported(algorithmId) },
) {
    override fun TestValidatorScope.validator(algorithm: Digest): DigestTestDataValidator = digests(
        hasher = algorithm.hasher(),
        digestSize = digestSize,
    )

    @Test
    fun abc() = test("abc") {
        digest(message = text("abc"), digest = hex(abcDigestHex))
    }

    @Test
    fun random() = test("random") { algorithm ->
        generateDigests(
            hasher = algorithm.hasher(),
            messageSizes = listOf(0) + (0..4).flatMap { n ->
                val maxSize = 10.0.pow(n).toInt()
                listOf(maxSize) + List(5) { CryptographyRandom.nextInt(maxSize) }
            } + 1_000_000,
        )
    }

    // API contract, nothing to store
    @Test
    fun functionBounds() = test("function-bounds", store = false) { algorithm ->
        val function = operation(
            operation = CreateFunctionTestOperation("HashFunction"),
            limitation = { failsIfIncrementalFunctionsUnsupported() },
        ) { algorithm.hasher().createHashFunction() }
        function.use {
            val array = ByteArray(10)
            assertFails { function.update(array, -1, 10) }
            assertFails { function.update(array, 0, -1) }
            assertFails { function.update(array, 20, 10) }
            assertFails { function.update(array, 0, 20) }
            function.update(array)
        }
    }
}
