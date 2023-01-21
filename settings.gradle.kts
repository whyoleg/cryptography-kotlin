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

rootProject.name = "cryptography-kotlin"

include("cryptography-io")
include("cryptography-random")
include("cryptography-core")

//providers
listOf("jdk", "apple", "webcrypto").forEach { name ->
    include("cryptography-providers:cryptography-$name")
    project(":cryptography-providers:cryptography-$name").projectDir = file("cryptography-providers/$name")
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
