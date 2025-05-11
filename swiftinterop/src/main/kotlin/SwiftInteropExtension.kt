/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.swiftinterop

import org.gradle.api.model.*
import org.gradle.api.provider.*
import javax.inject.*

abstract class SwiftInteropExtension @Inject constructor(objects: ObjectFactory) {
    val packageName: Property<String> = objects.property(String::class.java)

    val swiftToolsVersion: Property<String> = objects.property(String::class.java).convention("5.10")

    // TODO: make defaults equal to K/N values ?
    // TODO: rename to min*
    val iosVersion: Property<String> = objects.property(String::class.java)
    val macosVersion: Property<String> = objects.property(String::class.java)
    val tvosVersion: Property<String> = objects.property(String::class.java)
    val watchosVersion: Property<String> = objects.property(String::class.java)

    internal val swiftinteropModuleName = packageName.map { it.replace(".", "_") }
}
