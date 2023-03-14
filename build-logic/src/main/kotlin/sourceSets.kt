/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.gradle.api.*
import org.jetbrains.kotlin.gradle.dsl.*
import org.jetbrains.kotlin.gradle.plugin.*

//will be replaced with hierarchy with kotlin 1.8.20
fun KotlinMultiplatformExtension.sharedSourceSet(name: String, block: (KotlinTarget) -> Boolean) {
    sourceSets.shared(name, targets.filter(block))
}

fun NamedDomainObjectContainer<KotlinSourceSet>.shared(name: String, targets: List<KotlinTarget>) {
    if (targets.isEmpty()) return

    val main = create("${name}Main") {
        dependsOn(getByName("commonMain"))
    }
    val test = create("${name}Test") {
        dependsOn(getByName("commonTest"))
    }
    targets.forEach {
        getByName("${it.name}Main").dependsOn(main)
        getByName("${it.name}Test").dependsOn(test)
    }
}
