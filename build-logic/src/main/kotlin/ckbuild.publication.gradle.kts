/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    `maven-publish`
    signing
}

val sonatypeUsername: String? by project
val sonatypePassword: String? by project

val signingKey: String? by project
val signingPassword: String? by project

signing {
    isRequired = sonatypeUsername != null && sonatypePassword != null
    useInMemoryPgpKeys(signingKey, signingPassword)
    sign(publishing.publications)
}

val javadocJar by tasks.registering(Jar::class) { archiveClassifier.set("javadoc") }

// this is somewhat a hack because we have single javadoc artifact which is used for all publications
tasks.withType<Sign>().configureEach { mustRunAfter(javadocJar) }
tasks.withType<AbstractPublishToMaven>().configureEach { mustRunAfter(tasks.withType<Sign>()) }

publishing {
    repositories {
        maven {
            name = "snapshot"
            url = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/")
            credentials {
                username = sonatypeUsername
                password = sonatypePassword
            }
        }
        maven {
            name = "mavenCentral"
            url = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
            credentials {
                username = sonatypeUsername
                password = sonatypePassword
            }
        }
        maven {
            name = "projectLocal"
            url = uri(rootProject.layout.buildDirectory.dir("mavenProjectLocal"))
        }
    }

    publications.withType<MavenPublication>().configureEach {
        artifact(javadocJar)
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
}
