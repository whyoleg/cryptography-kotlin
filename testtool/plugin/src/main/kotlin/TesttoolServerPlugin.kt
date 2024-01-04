/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testtool.plugin

import com.android.build.gradle.internal.tasks.*
import org.gradle.api.*
import org.gradle.api.tasks.testing.*
import org.gradle.kotlin.dsl.*

open class TesttoolServerPlugin : Plugin<Project> {
    override fun apply(target: Project): Unit = with(target) {
        rootProject.apply<TesttoolServerRootPlugin>()

        val instance = TesttoolServerConfiguration(rootProject)
        val serverProvider = gradle.sharedServices.registerIfAbsent(
            "testtool-server-service",
            TesttoolServerService::class.java
        ) {
            it.parameters {
                it.instanceId.set(instance.instanceId)
                it.storage.set(instance.serverStorageDir)
            }
        }

        tasks.matching {
            it is AbstractTestTask || it is AndroidTestTask
        }.configureEach {
            it.doFirst {
                if (instance.instanceId.isPresent) serverProvider.get()
            }
            it.usesService(serverProvider)
        }
    }
}
