/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild

import org.gradle.api.*

object Projects {
    private enum class Tag { PUBLISHED, NOT_LIBRARY }

    private val projectTags: Map<String, Set<Tag>> = mapOf(
        "cryptography-bom" to setOf(Tag.PUBLISHED, Tag.NOT_LIBRARY),
        "cryptography-version-catalog" to setOf(Tag.PUBLISHED, Tag.NOT_LIBRARY),

        "cryptography-bigint" to setOf(Tag.PUBLISHED),
        "cryptography-random" to setOf(Tag.PUBLISHED),

        "cryptography-serialization-pem" to setOf(Tag.PUBLISHED),
        "cryptography-serialization-pem-benchmarks" to setOf(),
        "cryptography-serialization-asn1" to setOf(Tag.PUBLISHED),
        "cryptography-serialization-asn1-modules" to setOf(Tag.PUBLISHED),

        "cryptography-core" to setOf(Tag.PUBLISHED),

        "cryptography-provider-base" to setOf(Tag.PUBLISHED),
        "cryptography-provider-jdk" to setOf(Tag.PUBLISHED),
        "cryptography-provider-jdk-bc" to setOf(Tag.PUBLISHED),
        "cryptography-provider-apple" to setOf(Tag.PUBLISHED),
        "cryptography-provider-cryptokit" to setOf(Tag.PUBLISHED),
        "cryptography-provider-webcrypto" to setOf(Tag.PUBLISHED),
        "cryptography-provider-openssl3-api" to setOf(Tag.PUBLISHED),
        "cryptography-provider-openssl3-shared" to setOf(Tag.PUBLISHED),
        "cryptography-provider-openssl3-prebuilt" to setOf(Tag.PUBLISHED),
        "cryptography-provider-optimal" to setOf(Tag.PUBLISHED),

        "cryptography-provider-jdk-android-tests" to setOf(),
        "cryptography-provider-openssl3-test" to setOf(),
        "cryptography-provider-tests" to setOf(),
    )

    val published: Set<String> = projectTags.filter { Tag.PUBLISHED in it.value }.keys
    val libraries: Set<String> = projectTags.filter { Tag.PUBLISHED in it.value && Tag.NOT_LIBRARY !in it.value }.keys

    fun validateProjectTags(project: Project) {
        check(project == project.rootProject) { "Should be called only in rootProject" }
        val projectNames = project.subprojects.map(Project::getName).toSet()
        require(projectTags.keys == projectNames) {
            "Redundant projects: ${projectTags.keys - projectNames}\nMissing projects: ${projectNames - projectTags.keys}"
        }
    }
}
