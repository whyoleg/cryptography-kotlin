/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    id("org.jetbrains.dokka")
}

dokka {
    pluginsConfiguration.html {
        homepageLink.set("https://whyoleg.github.io/cryptography-kotlin")
    }

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
        externalDocumentationLinks.register("kotlinx-io") {
            url("https://kotlinlang.org/api/kotlinx-io/")
        }
    }
}

// root config - output and module aggregation
if (project == rootProject) {
    dokka {
        dokkaPublications.html {
            outputDirectory.set(file("docs/api"))
        }
    }
    dependencies {
        Projects.libraries.forEach {
            dokka(project(":$it"))
        }
    }
}
