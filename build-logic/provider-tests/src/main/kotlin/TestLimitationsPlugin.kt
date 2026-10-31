/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild.providertests

import ckbuild.teststorage.*
import org.gradle.api.*
import org.gradle.api.file.*
import org.gradle.kotlin.dsl.*

// limitations of providers observed in tests, see `UpdateTestLimitationsTask`
abstract class TestLimitationsPlugin : Plugin<Project> {
    override fun apply(target: Project): Unit = with(target) {
        val testStorageService = testStorageService()
        tasks.register<UpdateTestLimitationsTask>("updateTestLimitations") {
            usesService(testStorageService)
            testStorage.set(testStorageService)
            limitationsFile.set(testLimitationsFile())
            strict.set(providers.gradleProperty("ckbuild.testLimitations.strict").map(String::toBoolean).orElse(false))
        }
    }
}

fun Project.testLimitationsFile(): RegularFile = rootProject.layout.projectDirectory.file("limitations.json")
