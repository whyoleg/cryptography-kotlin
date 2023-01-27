enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
    includeBuild("gradle/plugins")
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

plugins {
    //this version can not be moved to version catalog, because it's in settings.gradle.kts
    id("com.gradle.enterprise") version "3.12.2"
}

gradleEnterprise {
    buildScan {
        termsOfServiceUrl = "https://gradle.com/terms-of-service"
        termsOfServiceAgree = "yes"
    }
}

rootProject.name = "cryptography-kotlin"

include("cryptography-bom")
include("cryptography-io")
include("cryptography-random")
include("cryptography-core")

//providers
listOf("jdk", "apple", "webcrypto", "openssl3").forEach { name ->
    include("cryptography-providers:cryptography-$name")
    project(":cryptography-providers:cryptography-$name").projectDir = file("cryptography-providers/$name")
}

listOf("dynamic", "static").forEach { name ->
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
