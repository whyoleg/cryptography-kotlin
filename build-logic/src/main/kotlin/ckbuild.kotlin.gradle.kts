/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import com.android.build.gradle.internal.tasks.*
import org.gradle.api.tasks.testing.*
import org.gradle.kotlin.dsl.*
import org.jetbrains.kotlin.gradle.dsl.*
import org.jetbrains.kotlin.gradle.plugin.*

plugins {
    id("org.jetbrains.kotlinx.kover")
}

val warningsAsErrors = booleanProperty("ckbuild.warningsAsErrors", defaultValue = true)
val skipTestTasks = booleanProperty("ckbuild.skipTestTasks", defaultValue = false)

plugins.withType<KotlinBasePluginWrapper>().configureEach {
    extensions.configure<KotlinProjectExtension>("kotlin") {

        fun KotlinCommonCompilerOptions.configureCommonOptions() {
            allWarningsAsErrors.set(warningsAsErrors)
            progressiveMode.set(true)
            freeCompilerArgs.addAll(
                "-Xrender-internal-diagnostic-names",
                "-Xreturn-value-checker=full"
            )
        }

        when (this) {
            is KotlinJvmProjectExtension    -> {
                compilerOptions {
                    configureCommonOptions()
                }
            }
            is KotlinMultiplatformExtension -> {
                compilerOptions {
                    configureCommonOptions()
                    freeCompilerArgs.add("-Xexpect-actual-classes")
                }
            }
        }

        // just applying `kotlin-test` doesn't work for JVM if there are multiple test tasks (like when we test on different JDKs)
        sourceSets.configureEach {
            when (name) {
                "commonTest"      -> "test"
                "jvmTest", "test" -> "test-junit"
                else              -> null
            }?.let { testDependency ->
                dependencies {
                    implementation(kotlin(testDependency))
                }
            }
        }
    }
}

tasks.matching { it is AbstractTestTask || it is AndroidTestTask || it.name == "koverVerify" }.configureEach {
    val skipTestTasks = skipTestTasks // for CC
    onlyIf { !skipTestTasks.get() }
}
