/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild.tests

import org.gradle.api.*
import org.gradle.api.tasks.*
import org.jetbrains.kotlin.gradle.dsl.*
import org.jetbrains.kotlin.gradle.plugin.*

fun Project.registerTestAggregationTask(
    name: String,
    taskDependencies: () -> TaskCollection<*>,
    targetFilter: (KotlinTarget) -> Boolean,
    configure: Task.() -> Unit = {},
) {
    extensions.configure<KotlinMultiplatformExtension>("kotlin") {
        var called = false
        targets.matching(targetFilter).configureEach {
            if (called) return@configureEach
            called = true

            tasks.register(name) {
                group = "verification"
                dependsOn(taskDependencies())
                configure()
            }
        }
    }
}
