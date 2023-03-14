/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    `java-platform`
    id("buildx-publish")
}

description = "cryptography-kotlin BOM"

dependencies {
    constraints {
        bom.libraries.forEach {
            api(project(it))
        }
    }
}

publishing {
    publications {
        val bom by creating(MavenPublication::class) {
            from(components["javaPlatform"])
        }
    }
}
