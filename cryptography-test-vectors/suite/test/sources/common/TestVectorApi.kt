package dev.whyoleg.cryptography.test.vectors.suite

sealed class TestVectorApi(
    val algorithm: String,
    val metadata: Map<String, String>, //todo
) {
    abstract val keys: TestVectorStorageApi
    abstract val keyPairs: TestVectorStorageApi
    abstract val digests: TestVectorStorageApi
    abstract val signatures: TestVectorStorageApi
    abstract val ciphers: TestVectorStorageApi
    abstract val derivedSecrets: TestVectorStorageApi
}
