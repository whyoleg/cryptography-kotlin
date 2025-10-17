/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.swiftinterop

import org.gradle.api.*

abstract class SwiftInteropPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        project.extensions.create("swiftInterop", SwiftInteropExtension::class.java, project)
    }
}
