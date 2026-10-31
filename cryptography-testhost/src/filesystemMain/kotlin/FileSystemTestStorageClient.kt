/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testhost

import kotlinx.io.*
import kotlinx.io.files.*

internal expect fun getenv(key: String): String?

internal class FileSystemTestStorageClient private constructor(
    private val root: Path,
    private val fileSystem: FileSystem,
) : TestStorageClient {
    constructor() : this(
        root = Path(
            requireNotNull(getenv("CK_FILESYSTEM_ROOT_PATH")) { "FILESYSTEM_ROOT_PATH environment variable is not set" }
        ),
        fileSystem = SystemFileSystem,
    )

    override suspend fun get(path: TestStorageClient.Path): String {
        val path = Path(root, *path)
        return fileSystem.source(path).buffered().use(Source::readString)
    }

    override suspend fun save(path: TestStorageClient.Path, content: String) {
        val path = Path(root, *path)
        fileSystem.createDirectories(path.parent!!)
        fileSystem.sink(path).buffered().use {
            it.writeString(content)
        }
    }

    override suspend fun list(path: TestStorageClient.Path): List<TestStorageClient.PathComponent> {
        val path = Path(root, *path)
        if (fileSystem.metadataOrNull(path)?.isDirectory != true) return emptyList()
        return fileSystem.list(path).filter {
            fileSystem.metadataOrNull(it)!!.isRegularFile
        }.map {
            it.name
        }
    }
}
