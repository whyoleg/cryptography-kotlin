/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.dokka.gradle.*
import org.jetbrains.kotlin.gradle.plugin.*
import java.net.*

plugins {
    id("buildx-multiplatform")
    id("buildx-publish")

    id("org.jetbrains.dokka")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
}

kotlin {
    explicitApi()

    //version enforcement using bom works only for jvm
    sourceSets.all {
        if (name == "jvmMain") dependencies {
            api(platform(project(":cryptography-bom")))
        }
    }
}

apiValidation {
    // in kotlin 1.9 Enum.entries were added because of which binary compatibility validator check fails
    validationDisabled = getKotlinPluginVersion().startsWith("1.9")
}

tasks.withType<DokkaTaskPartial>().configureEach {
    suppressInheritedMembers.set(true)
    failOnWarning.set(true)
    dokkaSourceSets.configureEach {
        includes.from("README.md")
        reportUndocumented.set(false) // set true later
        sourceLink {
            val sourceSetPath = "src/$name/kotlin"
            val relProjectPath = rootDir.toPath().relativize(projectDir.toPath())
            localDirectory.set(projectDir.resolve(sourceSetPath))
            remoteUrl.set(URL("https://github.com/whyoleg/cryptography-kotlin/tree/main/$relProjectPath/$sourceSetPath"))
            remoteLineSuffix.set("#L")
        }
    }
}

tasks.register<Copy>("copyForMkDocs") {
    from("README.md")
    into(rootDir.resolve("docs/modules"))
    rename { "${project.name}.md" }
}
