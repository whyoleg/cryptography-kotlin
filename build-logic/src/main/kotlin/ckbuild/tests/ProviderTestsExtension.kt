/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild.tests

import org.gradle.api.*
import org.gradle.api.provider.*
import org.gradle.api.tasks.*
import org.gradle.kotlin.dsl.*
import org.jetbrains.kotlin.gradle.dsl.*

abstract class ProviderTestsExtension {
    abstract val packageName: Property<String>
    abstract val imports: ListProperty<String>
    abstract val testClasses: ListProperty<String>

    // map key=`prefix for tests`, value=`provider initialization kotlin code`
    abstract val providerInitializers: MapProperty<String, String>
}

fun Project.configureProviderTestsExtension() {
    val providerTests = extensions.create<ProviderTestsExtension>("providerTests")
    registerGenerationProviderTestsTask(providerTests)
}

private fun Project.registerGenerationProviderTestsTask(extension: ProviderTestsExtension): TaskProvider<GenerateProviderTestsTask> {
    val generateProviderTestsTask = tasks.register<GenerateProviderTestsTask>("generateProviderTests") {
        packageName.set(extension.packageName)
        imports.set(extension.imports)
        // default testClasses if not set
        val defaults = listOf(
            "DefaultProviderTest",
            "SupportedAlgorithmsTest",

            "Pbkdf2CompatibilityTest",

            "HkdfCompatibilityTest",
            "HkdfTestvectorsTest",

            "DigestTest",
            "Md5CompatibilityTest",
            "Sha1CompatibilityTest",
            "Sha224CompatibilityTest",
            "Sha256CompatibilityTest",
            "Sha384CompatibilityTest",
            "Sha512CompatibilityTest",
            "Sha3B224CompatibilityTest",
            "Sha3B256CompatibilityTest",
            "Sha3B384CompatibilityTest",
            "Sha3B512CompatibilityTest",
            "Ripemd160CompatibilityTest",

            "AesCbcTest",
            "AesCbcCompatibilityTest",
            "AesCmacTest",
            "AesCmacCompatibilityTest",
            "AesCmacTestvectorsTest",
            "AesCtrTest",
            "AesCtrCompatibilityTest",
            "AesEcbCompatibilityTest",
            "AesGcmTest",
            "AesGcmCompatibilityTest",

            "HmacTest",
            "HmacCompatibilityTest",
            "HmacTestvectorsTest",

            "EdDsaTest",
            "XdhTest",

            "EcdsaTest",
            "EcdsaCompatibilityTest",
            "EcdhCompatibilityTest",

            "RsaOaepTest",
            "RsaOaepCompatibilityTest",
            "RsaPkcs1Test",
            "RsaPkcs1CompatibilityTest",
            "RsaPkcs1EsCompatibilityTest",
            "RsaPssTest",
            "RsaPssCompatibilityTest",
            "RsaRawCompatibilityTest",
        )
        testClasses.set(extension.testClasses.orElse(defaults))
        providerInitializers.set(extension.providerInitializers)
        outputDirectory.set(layout.buildDirectory.dir("generated/providerTests"))
    }

    tasks.maybeCreate("prepareKotlinIdeaImport").dependsOn(generateProviderTestsTask)

    extensions.configure<KotlinMultiplatformExtension>("kotlin") {
        sourceSets.commonTest {
            kotlin.srcDirs(generateProviderTestsTask)
        }
    }

    return generateProviderTestsTask
}
