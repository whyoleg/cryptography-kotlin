/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    kotlin("multiplatform") version "1.9.10"
}

kotlin {
    jvm()
    js {
        nodejs()
        browser()
    }

    val nativeTargets = listOf(
        mingwX64(),
        linuxX64(),
        macosX64(),
        macosArm64(),
    )

    sourceSets {
        commonMain {
            dependencies {
                implementation(cryptographyLibs.core)
            }
        }
        commonTest {
            dependencies {
                implementation(kotlin("test"))
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.7.3")
            }
        }
        val jsMain by getting {
            dependencies {
                implementation(cryptographyLibs.provider.webcrypto)
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation(cryptographyLibs.provider.jdk)
            }
        }
        val nativeMain by creating {
            dependsOn(commonMain.get())
            dependencies {
                implementation(cryptographyLibs.provider.openssl3.prebuilt)
            }
        }
        val nativeTest by creating {
            dependsOn(nativeMain)
            dependsOn(commonTest.get())
        }

        nativeTargets.forEach {
            getByName("${it.name}Main").dependsOn(nativeMain)
            getByName("${it.name}Test").dependsOn(nativeTest)
        }
    }
}
