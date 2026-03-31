/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    signing
    id("com.vanniktech.maven.publish.base")
}

mavenPublishing {
    publishToMavenCentral()
    signAllPublications()

    pom {
        name.set(project.name)
        description.set(provider {
            checkNotNull(project.description) { "Project description isn't set for project: ${project.path}" }
        })
        url.set("https://github.com/whyoleg/cryptography-kotlin")

        licenses {
            license {
                name.set("The Apache Software License, Version 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                distribution.set("repo")
            }
        }
        developers {
            developer {
                id.set("whyoleg")
                name.set("Oleg Yukhnevich")
                email.set("whyoleg@gmail.com")
            }
        }
        scm {
            connection.set("https://github.com/whyoleg/cryptography-kotlin.git")
            developerConnection.set("https://github.com/whyoleg/cryptography-kotlin.git")
            url.set("https://github.com/whyoleg/cryptography-kotlin")
        }
    }
}

// In most cases we ignore the singing requirement because:
// * we should be able to run `publishToMavenLocal` without signing;
// * signing is needed to Maven Central only, and it will anyway validate that the signature is present;
// * failure because of absent signature will anyway fail only on CI during publishing release;
// Still, it makes sense to enable signing check during publication, specifically to fail during SNAPSHOT publication
signing.isRequired = booleanProperty("ckbuild.requireSigning", defaultValue = false).get()
