/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:Suppress("UnstableApiUsage")

pluginManagement {
    repositories {
        google {
            content {
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
                includeGroupAndSubgroups("androidx")
            }
        }
        mavenCentral()
        gradlePluginPortal()

        maven("https://packages.jetbrains.team/maven/p/kt/dokka-dev") {
            content {
                includeGroupAndSubgroups("org.jetbrains.dokka")
            }
        }
//        maven("https://central.sonatype.com/api/v1/publisher/deployments/download/") {
//            content {
//                includeGroupAndSubgroups("org.jetbrains.dokka")
//            }
//            // maven central config:
//            name = "central"
//            credentials(HttpHeaderCredentials::class)
//            authentication.create<HttpHeaderAuthentication>("header")
//        }
    }
}

dependencyResolutionManagement {
    repositories {
        google {
            content {
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
                includeGroupAndSubgroups("androidx")
            }
        }
        mavenCentral()
        gradlePluginPortal()

        maven("https://packages.jetbrains.team/maven/p/kt/dokka-dev") {
            content {
                includeGroupAndSubgroups("org.jetbrains.dokka")
            }
        }
//        maven("https://central.sonatype.com/api/v1/publisher/deployments/download/") {
//            content {
//                includeGroupAndSubgroups("org.jetbrains.dokka")
//            }
//            // maven central config:
//            name = "central"
//            credentials(HttpHeaderCredentials::class)
//            authentication.create<HttpHeaderAuthentication>("header")
//        }
    }
}
