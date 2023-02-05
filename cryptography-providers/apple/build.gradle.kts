plugins {
    id("buildx-multiplatform-provider")
    id("org.jetbrains.dokka")
}

description = "cryptography-kotlin Apple provider"

kotlin {
    appleTargets()
}
