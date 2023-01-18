package dev.whyoleg.cryptography.test.vectors.suite.api

sealed class TestVectorApi {
    abstract val keys: TestVectorStorageApi
    abstract val keyPairs: TestVectorStorageApi
    abstract val digests: TestVectorStorageApi
    abstract val signatures: TestVectorStorageApi
    abstract val ciphers: TestVectorStorageApi
//    abstract val derivedSecrets: TestVectorStorageApi
}
