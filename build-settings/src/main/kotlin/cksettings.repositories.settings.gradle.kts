/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
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
        gradlePluginPortal {
            content {
                includeGroupAndSubgroups("com.gradle")
                includeGroupAndSubgroups("org.gradle")
            }
        }
        mavenCentral()
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
        gradlePluginPortal {
            content {
                includeGroupAndSubgroups("com.gradle")
                includeGroupAndSubgroups("org.gradle")
            }
        }
        mavenCentral()
    }
}
