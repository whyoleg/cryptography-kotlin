/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testhost

interface TestStorageClient {
    companion object {
        fun logging(delegate: TestStorageClient): TestStorageClient = LoggingTestStorageClient(delegate)
        fun noop(): TestStorageClient = NoopTestStorageClient
        fun default(): TestStorageClient = defaultTestStorageClient
    }

    typealias Path = Array<PathComponent>
    typealias PathComponent = String

    suspend fun get(path: Path): String
    suspend fun save(path: Path, content: String)

    // returns only files; returns an empty list if the directory doesn't exist
    suspend fun list(path: Path): List<PathComponent>
}

internal expect val defaultTestStorageClient: TestStorageClient

private object NoopTestStorageClient : TestStorageClient {
    override suspend fun get(path: TestStorageClient.Path): String {
        error("NoopTestStorage.get is impossible")
    }

    override suspend fun save(path: TestStorageClient.Path, content: String) {
        // skip
    }

    override suspend fun list(path: TestStorageClient.Path): List<TestStorageClient.PathComponent> {
        error("NoopTestStorage.list is impossible")
    }
}

private class LoggingTestStorageClient(
    private val delegate: TestStorageClient,
) : TestStorageClient {
    override suspend fun get(path: TestStorageClient.Path): String {
        return delegate.get(path).also { content ->
            println("get(${path.joinToString("/")}): $content")
        }
    }

    override suspend fun save(path: TestStorageClient.Path, content: String) {
        println("save(${path.joinToString("/")}): $content")
        delegate.save(path, content)
    }

    override suspend fun list(path: TestStorageClient.Path): List<TestStorageClient.PathComponent> {
        return delegate.list(path).also {
            println("list(${path.joinToString("/")}): $it")
        }
    }
}
