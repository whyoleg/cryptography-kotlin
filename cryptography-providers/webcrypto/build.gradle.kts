plugins {
    id("buildx-multiplatform-provider")
    id("org.jetbrains.dokka")
}

description = "cryptography-kotlin WebCrypto provider"

kotlin {
    jsTargets()
}
