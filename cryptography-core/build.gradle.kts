import org.jetbrains.kotlin.gradle.plugin.*

plugins {
    id("buildx-multiplatform-library")
}

kotlin {
    jvm()
    js {
        browser()
        nodejs()
    }
    val nativeTargets = listOf(
        linuxX64(),
        macosX64(),
        macosArm64(),
        mingwX64()
    )

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
        shared("native", nativeTargets)

        commonMain {
            dependencies {
                api(projects.cryptographyIo)
            }
        }
    }
}
