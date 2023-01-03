import org.jetbrains.kotlin.gradle.plugin.*

plugins {
    id("buildx-multiplatform")
}

kotlin {
    jvm()
    js {
        browser()
        nodejs()
    }
    val linuxTargets = listOf(linuxX64())
    val darwinTargets = listOf(macosX64(), macosArm64())
    val mingwTargets = listOf(mingwX64())

    sourceSets {
        fun shared(name: String, targets: List<KotlinTarget>) {
            val main = create("${name}Main") {
                dependsOn(commonMain.get())
            }
            val test = create("${name}Test") {
                dependsOn(commonTest.get())
            }
            targets.forEach {
                getByName("${it.name}Main").dependsOn(main)
                getByName("${it.name}Test").dependsOn(test)
            }
        }
        shared("linux", linuxTargets)
        shared("darwin", darwinTargets)
        shared("mingw", mingwTargets)
    }
}
