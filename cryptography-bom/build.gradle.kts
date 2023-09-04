/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    `java-platform`
    id("ckbuild.publish")
}

description = "cryptography-kotlin BOM"

dependencies {
    constraints {
        ckbuild.bom.artifacts.forEach {
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
