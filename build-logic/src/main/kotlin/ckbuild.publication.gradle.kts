/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

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

// we ignore the singing requirement because:
// * we should be able to run `publishToMavenLocal` without signing;
// * signing is needed to Maven Central only, and it will anyway validate that the signature is present;
// * failure because of absent signature will anyway fail only on CI during publishing release;
signing.isRequired = false

// javadocJar setup
// we have a single javadoc artifact which is used for all publications,
// and so we need to manually create task dependencies to make Gradle happy
val javadocJar by tasks.registering(Jar::class) { archiveClassifier.set("javadoc") }
tasks.withType<Sign>().configureEach { dependsOn(javadocJar) }
tasks.withType<AbstractPublishToMaven>().configureEach { mustRunAfter(tasks.withType<Sign>()) }
publishing.publications.withType<MavenPublication>().configureEach { artifact(javadocJar) }
