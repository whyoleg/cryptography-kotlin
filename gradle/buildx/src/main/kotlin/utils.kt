import org.gradle.api.*
import org.gradle.api.file.*
import org.jetbrains.kotlin.gradle.dsl.*
import org.jetbrains.kotlin.gradle.plugin.*

fun SourceDirectorySet.dir(path: String) = setSrcDirs(listOf(path))

fun KotlinMultiplatformExtension.sharedSourceSet(name: String, block: (KotlinTarget) -> Boolean) {
    sourceSets.shared(name, targets.filter(block))
}

fun NamedDomainObjectContainer<KotlinSourceSet>.shared(name: String, targets: List<KotlinTarget>) {
    if (targets.isEmpty()) return

    val main = create("${name}Main") {
        dependsOn(getByName("commonMain"))
    }
    val test = create("${name}Test") {
        dependsOn(getByName("commonTest"))
    }
    targets.forEach {
        getByName("${it.name}Main").dependsOn(main)
        getByName("${it.name}Test").dependsOn(test)
    }
}

fun KotlinMultiplatformExtension.jsTargets() {
    js {
        nodejs {
            testTask {
                useMocha {
                    timeout = "600s"
                }
            }
        }
        browser {
            testTask {
                useKarma {
                    useConfigDirectory(project.rootDir.resolve("gradle").resolve("karma.config.d"))
                    useChromeHeadless()
//                        useSafari()
                }
            }
        }
    }
}

fun KotlinMultiplatformExtension.darwinTargets() {
    macosX64()
    macosArm64()
}

fun KotlinMultiplatformExtension.allTargets() {
    jvm()
    jsTargets()
    darwinTargets()
    linuxX64()
    mingwX64()
}
