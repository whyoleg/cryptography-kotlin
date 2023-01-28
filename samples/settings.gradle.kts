pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenLocal()
        mavenCentral()
    }

    versionCatalogs {
        val libsCryptography by creating {
            from("dev.whyoleg.cryptography:cryptography-version-catalog:0.1.0")
        }
    }
}

rootProject.name = "cryptography-kotlin-samples"

include("openssl3-dynamic")
include("openssl3-static")
