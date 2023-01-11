package dev.whyoleg.cryptography.testcase.main

import dev.whyoleg.cryptography.algorithms.asymmetric.ec.*
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import kotlin.test.*

class EcTest {
    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun test() = runTest {
        supportedProviders.forEach {
            val algorithm = it.get(ECDSA)

            val publicKey =
                algorithm.keyPairGenerator(EC.Curve.P521)
                    .generateKey()
                    .publicKey.encodeTo(EC.PublicKey.Format.DER)

            val pk = algorithm.publicKeyDecoder(EC.Curve.P384)
                .decodeFrom(EC.PublicKey.Format.DER, publicKey)
        }
    }
}
