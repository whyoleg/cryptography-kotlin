package dev.whyoleg.cryptography.test.suite

import dev.whyoleg.cryptography.test.api.*

class LocalCryptographyTest : CryptographyTest(TestStep.Generate, TestStep.Compute, TestStep.Validate) {
    override fun api(metadata: Map<String, String>): Api = InMemoryApi(metadata)
}

private class InMemoryApi(override val metadata: Map<String, String>) : Api {
    override val keys: Api.SubApi<KeyData> = api("keys")
    override val keyPairs: Api.SubApi<KeyPairData> = api("key-pairs")
    override val digests: Api.SubApi<DigestData> = api("digests")
    override val signatures: Api.SubApi<SignatureData> = api("signatures")
    override val ciphers: Api.SubApi<CipherData> = api("ciphers")

    private fun <T> api(path: String) = InMemorySubApi<T>(path, metadata, storage(path))

    private companion object {
        private val map = mutableMapOf<String, InMemoryStorage<*>>()
        fun <T> storage(path: String): InMemoryStorage<T> = map.getOrPut(path) { InMemoryStorage<T>() } as InMemoryStorage<T>
    }
}

private class InMemorySubApi<T>(
    private val path: String,
    private val metadata: Map<String, String>,
    private val storage: InMemoryStorage<T>,
) : Api.SubApi<T> {
    override suspend fun save(algorithm: String, params: String, data: T, metadata: Map<String, String>): String {
        try {
            val payload = Payload(this.metadata + metadata, data)
            val id = storage.save(algorithm, params, payload)
            println("save: $path/$algorithm/$params -> $id | $metadata")
            return id
        } catch (cause: Throwable) {
            println("save[FAILED]: $path/$algorithm/$params | $metadata")
            throw cause
        }
    }

    override suspend fun get(algorithm: String, params: String, id: String): Payload<T> {
        try {
            val payload = storage.get(algorithm, params, id)
            println("get: $path/$algorithm/$params/$id | ${payload.metadata}")
            return payload
        } catch (cause: Throwable) {
            println("get[FAILED]: $path/$algorithm/$params/$id")
            throw cause
        }
    }

    override suspend fun getAll(algorithm: String, params: String): List<Payload<T>> {
        println("getAll: $path/$algorithm/$params")
        return storage.getAll(algorithm, params)
    }
}

private class InMemoryStorage<T> {
    private val map: MutableMap<String, MutableMap<String, Payload<T>>> = mutableMapOf()
    private var id = 0

    fun save(algorithm: String, params: String, payload: Payload<T>): String {
        val id = this.id++.toString()
        map.getOrPut(algorithm + params, ::mutableMapOf)[id] = payload
        return id
    }

    fun get(algorithm: String, params: String, id: String): Payload<T> = map[algorithm + params]!![id]!!

    fun getAll(algorithm: String, params: String): List<Payload<T>> = map[algorithm + params]?.values?.toList().orEmpty()
}
