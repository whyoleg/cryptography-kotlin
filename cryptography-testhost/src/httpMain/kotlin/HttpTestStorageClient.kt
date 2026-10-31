/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testhost

import io.ktor.client.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.client.statement.*

// for Android
internal expect fun hostOverride(): String?

internal class HttpTestStorageClient private constructor(
    private val client: HttpClient,
) : TestStorageClient {
    constructor() : this(
        client = HttpClient {
            expectSuccess = true
            install(DefaultRequest) {
                host = hostOverride() ?: ""
                port = 9000
            }
        }
    )

    override suspend fun save(path: TestStorageClient.Path, content: String) {
        val path = path.joinToString("/")
        client.post("save") {
            url { parameter("path", path) }
            setBody(content)
        }
    }

    override suspend fun get(path: TestStorageClient.Path): String {
        val path = path.joinToString("/")
        return client.get("get") {
            url { parameter("path", path) }
        }.bodyAsText()
    }

    override suspend fun list(path: TestStorageClient.Path): List<TestStorageClient.PathComponent> {
        val path = path.joinToString("/")
        return client.get("list") {
            url { parameter("path", path) }
        }.bodyAsText().split('\n').filter(String::isNotEmpty)
    }
}
