/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    kotlin("multiplatform")
    id("org.jetbrains.dokka")
}

dokka {
    setupHomepageLink()

    dokkaPublications.configureEach {
        // we don't suppress inherited members explicitly as without it classes like RSA.OAEP don't show functions like keyGenerator
        suppressInheritedMembers = false
        failOnWarning = true
    }
    dokkaSourceSets.configureEach {
        includes.from(rootDir.resolve("dokka/modules.md"))
        reportUndocumented = false // set true later
        skipDeprecated = true
        sourceLink {
            localDirectory = rootDir
            remoteUrl("https://github.com/whyoleg/cryptography-kotlin/tree/$version/")
        }

        if (name.endsWith("Main")) {
            samples.from("src/${name.replace("Main", "Samples")}/kotlin")
        }
    }
}

kotlin {
    sourceSets.configureEach {
        if (name.endsWith("Test")) {
            kotlin.srcDir("src/${name.replace("Test", "Samples")}/kotlin")
        }
    }
}
