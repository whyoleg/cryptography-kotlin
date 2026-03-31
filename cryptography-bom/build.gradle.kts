/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import com.vanniktech.maven.publish.*

plugins {
    `java-platform`
    id("ckbuild.publication")
}

description = "cryptography-kotlin BOM"

mavenPublishing {
    configure(JavaPlatform())
}

dependencies {
    constraints {
        Projects.libraries.forEach {
            api(project(":$it"))
        }
    }
}
