package dev.whyoleg.cryptography.test.vectors.suite.tests

//import dev.whyoleg.cryptography.random.*
//import dev.whyoleg.cryptography.test.api.*
//import dev.whyoleg.cryptography.test.suite.*
//import dev.whyoleg.cryptography.test.suite.generators.*
//
//private const val iterations = 100
//private const val maxDataSize = 10000
//
//private val generate = TestAction { api, provider ->
//    digests { digestCryptographyAlgorithmId, _ ->
//        val algorithm = provider.get(digestCryptographyAlgorithmId)
//        val hasher = algorithm.hasher()
//
//        repeat(iterations) {
//            val dataSize = CryptographyRandom.nextInt(maxDataSize)
//            println("generate: data.size  = $dataSize")
//            val data = CryptographyRandom.nextBytes(dataSize)
//            val digest = hasher.hash(data)
//            println("generate: digest.size  = ${digest.size}")
//            hasher.hash(data).assertContentEquals(digest)
//
//            api.digests.save(
//                algorithm = algorithm.id.name,
//                params = "x", //TODO
//                data = DigestData(data, digest)
//            )
//        }
//    }
//}
//
//private val validate = TestAction { api, provider ->
//    digests { digestCryptographyAlgorithmId, _ ->
//        val algorithm = provider.get(digestCryptographyAlgorithmId)
//        val hasher = algorithm.hasher()
//
//        api.digests.getAll(
//            algorithm = algorithm.id.name,
//            params = "x" //TODO
//        ).forEach { (digest) ->
//            hasher.hash(digest.data).assertContentEquals(digest.digest)
//        }
//    }
//}
//
//val digest = TestSuite("Digest", generate = generate, validate = validate)
