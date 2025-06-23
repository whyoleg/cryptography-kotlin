/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    `java-platform`
    id("ckbuild.publication")
}

description = "cryptography-kotlin BOM"

dependencies {
    constraints {
        Projects.libraries.forEach {
            api(project(":$it"))
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
