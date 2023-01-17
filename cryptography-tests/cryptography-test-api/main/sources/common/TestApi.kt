package dev.whyoleg.cryptography.test.api

//interface TestApi {
//    val metadata: Map<String, String>
//
//    val keys: TestStorageApi<KeyData>
//    val keyPairs: TestStorageApi<KeyPairData>
//    val digests: TestStorageApi<DigestData>
//    val ciphers: TestStorageApi<CipherData>
//    val signatures: TestStorageApi<SignatureData>
//}

interface TestStorageApi<M, D> {
    suspend fun saveMeta(algorithm: String, meta: M): String
    suspend fun saveData(algorithm: String, metaId: String, data: D): String
    suspend fun get(algorithm: String, params: String, id: String): Payload<T>
    suspend fun getAll(algorithm: String, params: String): List<Payload<T>>
}

interface TestMetaApi<M> {
    suspend fun save(algorithm: String, meta: M): String
//    suspend fun get(algorithm: String): Flow<>
}
