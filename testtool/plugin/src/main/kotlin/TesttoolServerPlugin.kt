/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testtool.plugin

import com.android.build.gradle.internal.tasks.*
import org.gradle.api.*
import org.gradle.api.file.*
import org.gradle.api.provider.*
import org.gradle.api.tasks.*
import org.gradle.api.tasks.bundling.*
import org.gradle.api.tasks.testing.*
import org.gradle.kotlin.dsl.*
import org.jetbrains.kotlin.gradle.dsl.*

open class TesttoolServerPlugin : Plugin<Project> {

    override fun apply(target: Project): Unit = with(target) {
        val serverStorage = configureRootProject(rootProject)
        val serverInstanceId = the<buildparameters.BuildParametersExtension>().testtool.instanceId
        val serverProvider = gradle.sharedServices.registerIfAbsent(
            "testtool-server-service",
            TesttoolServerService::class.java
        ) {
            it.parameters {
                it.instanceId.set(serverInstanceId)
                it.storage.set(serverStorage)
            }
        }

        tasks.matching {
            it is AbstractTestTask || it is AndroidTestTask
        }.configureEach {
            it.doFirst {
                if (serverInstanceId.isPresent) serverProvider.get()
            }
            it.usesService(serverProvider)
        }

        plugins.withId("org.jetbrains.kotlin.multiplatform") {
            extensions.configure<KotlinMultiplatformExtension>("kotlin") {
                it.sourceSets.named("commonTest") {
                    it.dependencies {
                        implementation("testtool:client")
                    }
                }
            }
        }
    }

    private fun configureRootProject(project: Project): Provider<Directory> = with(project) {
        require(project == rootProject) { "Root project required" }

        val instanceId = the<buildparameters.BuildParametersExtension>().testtool.instanceId
        val buildDir = layout.buildDirectory.dir("testtool")
        val serverStorageDir = buildDir.map { it.dir("server-storage") }
        val serverStorageDumpDir = buildDir.map { it.dir("server-storage-dump") }

        tasks.register<Delete>("cleanTesttool") {
            delete(buildDir)
        }

        tasks.register<Zip>("dumpTesttoolServerStorage") {
            onlyIf { instanceId.isPresent }

            archiveFileName.set(instanceId.map { "$it.zip" })
            destinationDirectory.set(serverStorageDumpDir)
            from(serverStorageDir)
        }

        tasks.register<Copy>("restoreTesttoolServerStorage") {
            from(fileTree(serverStorageDumpDir) {
                it.include("*.zip")
            }.map(::zipTree))

            into(serverStorageDir)
        }

        serverStorageDir
    }
}
