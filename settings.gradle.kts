enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
    includeBuild("gradle/plugins")
    includeBuild("gradle/build-parameters")
    includeBuild("gradle/kotlin-version-catalog")
}

plugins {
    id("kotlin-version-catalog")
    id("com.gradle.enterprise") version "3.12.2"
}

dependencyResolutionManagement {
    repositories {
        mavenLocal {
            content {
                includeGroup("dev.whyoleg.kcwrapper")
            }
        }
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots/") {
            content {
                includeGroup("dev.whyoleg.kcwrapper")
            }
        }
        mavenCentral()
    }

    versionCatalogs {
        create("kcwrapperLibs") {
            from("dev.whyoleg.kcwrapper:kcwrapper-version-catalog:0.1.0-SNAPSHOT")
        }
    }
}

gradleEnterprise {
    buildScan {
        termsOfServiceUrl = "https://gradle.com/terms-of-service"
        termsOfServiceAgree = "yes"
    }
}

rootProject.name = "cryptography-kotlin"

include("cryptography-bom")
include("cryptography-version-catalog")
include("cryptography-random")
include("cryptography-core")

//providers
listOf("jdk", "apple", "webcrypto").forEach { name ->
    include("cryptography-providers:cryptography-$name")
    project(":cryptography-providers:cryptography-$name").projectDir = file("cryptography-providers/$name")
}

listOf("api", "dynamic", "static").forEach { name ->
    include("cryptography-providers:cryptography-openssl3:cryptography-openssl3-$name")
    project(":cryptography-providers:cryptography-openssl3:cryptography-openssl3-$name").projectDir =
        file("cryptography-providers/openssl3/$name")
}

//tests
listOf(
    "test-utils",
    "behavior-tests",
    "compatibility-tests"
).forEach { name ->
    include("cryptography-tests:cryptography-$name")
    project(":cryptography-tests:cryptography-$name").projectDir = file("cryptography-tests/$name")
}

//test tool
listOf("client", "server").forEach { name ->
    include("cryptography-tester:cryptography-tester-$name")
    project(":cryptography-tester:cryptography-tester-$name").projectDir = file("cryptography-tester/$name")
}
