package dev.whyoleg.cryptography.test.vectors.suite.tests

import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.test.vectors.suite.api.*

class AesCbcTest : TestVectorTest("AES-CBC") {
    override suspend fun generate(api: TestVectorApi, provider: CryptographyProvider) {
        println("GENERATE")
    }

    override suspend fun validate(api: TestVectorApi, provider: CryptographyProvider) {
        println("VALIDATE")
    }
}
