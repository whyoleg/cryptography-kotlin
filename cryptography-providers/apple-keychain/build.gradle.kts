import ckbuild.*
import org.jetbrains.kotlin.gradle.*

plugins {
    id("ckbuild.multiplatform-library")
}

description = "cryptography-kotlin Apple Keychain-backed KeyStore (experimental)"

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    appleTargets()

    compilerOptions {
        optIn.addAll(
            OptIns.DelicateCryptographyApi,
            OptIns.CryptographyProviderApi,
            OptIns.ExperimentalForeignApi,
        )
    }

    sourceSets.commonMain.dependencies {
        api(projects.cryptographyCore)
        api(projects.cryptographyStorage)
        implementation(projects.cryptographyProviderBase)
    }

    sourceSets.commonTest.dependencies {
        implementation(kotlin("test"))
    }
}
