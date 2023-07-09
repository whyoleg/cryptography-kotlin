/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testtool.plugin

import org.gradle.api.*
import org.gradle.api.tasks.testing.*
import org.gradle.kotlin.dsl.*
import org.jetbrains.kotlin.gradle.dsl.*

open class TesttoolServerPlugin : Plugin<Project> {

    override fun apply(target: Project): Unit = target.run {
        val buildParameters = the<buildparameters.BuildParametersExtension>()
        val testtoolServerInstanceId = buildParameters.testtool.instanceId
        val testtoolServerStorage = rootProject.layout.buildDirectory.dir("test-tool-storage")

        rootProject.tasks.register("cleanTesttoolServerStorage") {
            doLast {
                testtoolServerStorage.get().asFile.deleteRecursively()
            }
        }

        val serverProvider = gradle.sharedServices.registerIfAbsent(
            "testtool-server",
            TesttoolServerService::class.java
        ) {
            parameters {
                instanceId.set(testtoolServerInstanceId)
                storage.set(testtoolServerStorage)
            }
        }

        fun useServer(task: Task): Unit = task.run {
            doFirst {
                if (testtoolServerInstanceId.isPresent) serverProvider.get()
            }
            usesService(serverProvider)
        }

        tasks.withType<AbstractTestTask>().configureEach(::useServer)
//        TODO: android
//        tasks.withType<AndroidTestTask>().configureEach(::useServer)

        plugins.withId("org.jetbrains.kotlin.multiplatform") {
            extensions.configure<KotlinMultiplatformExtension>("kotlin") {
                sourceSets.named("commonTest") {
                    dependencies {
                        implementation("testtool:client")
                    }
                }
            }
        }
    }
}
