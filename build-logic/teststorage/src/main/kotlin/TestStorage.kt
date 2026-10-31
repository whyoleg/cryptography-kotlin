/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild.teststorage

import java.nio.file.*
import kotlin.io.path.*

// file system access to the test storage, similar to `TestStorageClient` in `cryptography-testhost`
class TestStorage internal constructor(directory: Path) {
    private val directory = directory.toAbsolutePath().normalize()

    fun get(path: List<String>): String = resolve(path).readText()

    fun save(path: List<String>, content: String) {
        resolve(path).createParentDirectories().writeText(content)
    }

    // deletes the file or the directory recursively
    @OptIn(ExperimentalPathApi::class)
    fun delete(path: List<String>) {
        resolve(path).deleteRecursively()
    }

    // returns only files; returns an empty list if the directory doesn't exist
    fun list(path: List<String>): List<String> = entries(path, Path::isRegularFile)

    // returns only directories; returns an empty list if the directory doesn't exist
    fun directories(path: List<String>): List<String> = entries(path, Path::isDirectory)

    private fun entries(path: List<String>, filter: (Path) -> Boolean): List<String> =
        resolve(path).takeIf(Path::isDirectory)?.listDirectoryEntries().orEmpty().filter(filter).map(Path::name).sorted()

    internal fun resolve(path: List<String>): Path = directory.resolve(path.joinToString("/")).normalize().also {
        require(it.startsWith(directory)) { "Path '$path' is outside of test storage" }
    }
}
