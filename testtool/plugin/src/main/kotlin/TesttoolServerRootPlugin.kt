/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testtool.plugin

import org.gradle.api.*
import org.gradle.api.tasks.*
import org.gradle.api.tasks.bundling.*
import org.gradle.kotlin.dsl.*

open class TesttoolServerRootPlugin : Plugin<Project> {
    override fun apply(target: Project): Unit = with(target) {
        require(project == rootProject) { "Root project required" }

        val instance = TesttoolServerConfiguration(project)

        tasks.register<Delete>("cleanTesttool") {
            delete(instance.buildDir)
        }

        tasks.register<Zip>("dumpTesttoolServerStorage") {
            onlyIf { instance.instanceId.isPresent }

            archiveFileName.set(instance.instanceId.map { "$it.zip" })
            destinationDirectory.set(instance.serverStorageDumpDir)
            from(instance.serverStorageDir)
        }

        tasks.register<Copy>("restoreTesttoolServerStorage") {
            from(fileTree(instance.serverStorageDumpDir) {
                it.include("*.zip")
            }.map(::zipTree))

            into(instance.serverStorageDir)
        }
    }
}
