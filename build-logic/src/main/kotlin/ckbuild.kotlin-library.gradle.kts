/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:OptIn(ExperimentalAbiValidation::class)

import org.jetbrains.kotlin.gradle.dsl.*
import org.jetbrains.kotlin.gradle.dsl.abi.*
import org.jetbrains.kotlin.gradle.plugin.*

plugins {
    id("ckbuild.kotlin")
    id("ckbuild.publication")
    id("ckbuild.dokka")
}

plugins.withType<KotlinBasePluginWrapper>().configureEach {
    extensions.configure<KotlinProjectExtension>("kotlin") {
        explicitApi()
        // register samples as tests
        sourceSets.configureEach {
            if (name == "test") {
                kotlin.srcDir("src/samples/kotlin")
            } else if (name.endsWith("Test")) {
                kotlin.srcDir("src/${name.replace("Test", "Samples")}/kotlin")
            }
        }
    }
}

dokka {
    // register samples as samples
    dokkaSourceSets.configureEach {
        if (name == "main") {
            samples.from("src/samples/kotlin")
        } else if (name.endsWith("Main")) {
            samples.from("src/${name.replace("Main", "Samples")}/kotlin")
        }
    }
}
