package dev.whyoleg.cryptography.test.client

import dev.whyoleg.cryptography.test.api.*
import kotlinx.coroutines.*
import kotlin.random.*

fun main(): Unit = runBlocking {
    val client = HttpApi(mapOf("engine" to "JDK", "platform" to "JVM"))
    val algorithm = "AES-GCM"
    val key = KeyData(
        mapOf(
            "RAW" to Random.nextBytes(256),
            "JWK" to Random.nextBytes(123),
        )
    )
    val keyId1 = client.keys.save(algorithm, "B256", key)
    val keyId2 = client.keys.save(algorithm, "B256", key)
    client.keys.save(algorithm, "B512", key)
    println(keyId1)
    println(keyId2)

    val data2 = client.keys.get(algorithm, "B256", keyId1)
    println(key.formats.values.first().contentToString())
    println(data2.data.formats.values.first().contentToString())

    val cipherId1 = client.ciphers.save(
        algorithm, "TAG-16",
        CipherData(keyId2, Random.nextBytes(256), Random.nextBytes(256))
    )

    val cipherId2 = client.ciphers.save(
        algorithm, "TAG-32",
        CipherData(keyId1, Random.nextBytes(256), Random.nextBytes(256))
    )
    println(cipherId1)
    println(cipherId2)

    println(client.ciphers.get(algorithm, "TAG-16", cipherId1).data.keyId)
    println(client.ciphers.get(algorithm, "TAG-32", cipherId2).data.keyId)
}
