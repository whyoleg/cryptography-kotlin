/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testtool.server

import org.gradle.api.*
import org.gradle.kotlin.dsl.*
import org.jetbrains.kotlin.gradle.dsl.*
import org.jetbrains.kotlin.gradle.plugin.*
import org.jetbrains.kotlin.gradle.targets.js.ir.*

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
            TesttoolServer::class.java
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

        plugins.withId("org.jetbrains.kotlin.multiplatform") {
            val kotlin = extensions.getByName("kotlin") as KotlinMultiplatformExtension
            kotlin.targets.all {
                if (this is KotlinTargetWithTests<*, *>) {
                    testRuns.all { (this as ExecutionTaskHolder<*>).executionTask.configure(::useServer) }
                    if (this is KotlinJsIrTarget) {
                        browser.testRuns.all { executionTask.configure(::useServer) }
                        nodejs.testRuns.all { executionTask.configure(::useServer) }
                    }
                }
            }
        }
    }
}
