/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testtool.plugin

import org.gradle.api.*
import org.gradle.api.file.*
import org.gradle.api.provider.*

class TesttoolServerConfiguration(rootProject: Project) {
    init {
        require(rootProject == rootProject.rootProject) { "Root project required" }
    }

    val instanceId: Provider<String> = rootProject.providers.gradleProperty("ckbuild.testtool.instanceId")
    val buildDir: Provider<Directory> = rootProject.layout.buildDirectory.dir("testtool")
    val serverStorageDir: Provider<Directory> = buildDir.map { it.dir("server-storage") }
    val serverStorageDumpDir: Provider<Directory> = buildDir.map { it.dir("server-storage-dump") }
}
