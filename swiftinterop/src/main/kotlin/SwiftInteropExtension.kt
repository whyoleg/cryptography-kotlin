/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.swiftinterop

import org.gradle.api.*
import org.jetbrains.kotlin.gradle.plugin.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*

abstract class SwiftInteropExtension(project: Project) {
    val products = project.objects.domainObjectContainer(
        SwiftInteropProduct::class.java,
        SwiftInteropProduct.factory(project)
    )
}

fun KotlinNativeTarget.swiftInterop(
    productName: String, // required
    compilationName: String = "main",
    block: CInteropSettings.() -> Unit = {},
) {
    compilations.getByName(compilationName).swiftInterop(productName, block)
}

fun KotlinNativeCompilation.swiftInterop(
    productName: String, // required
    block: CInteropSettings.() -> Unit = {},
) {
    project.extensions.getByType(SwiftInteropExtension::class.java)
        .products.maybeCreate(productName)
        .setupCInterop(this, block)
}
