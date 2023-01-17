import gradle.kotlin.dsl.accessors._1c8707824c48c16ed0a1f292cf6be26b.*
import org.gradle.jvm.toolchain.*
import org.jetbrains.kotlin.gradle.targets.jvm.*

fun KotlinJvmTarget.setupTests() {
    //setup additional testing on different JDK versions (default task jvmTest will run on JDK8)
    listOf(11, 17).forEach { jdkVersion ->
        testRuns.create("${jdkVersion}Test") {
            executionTask.configure {
                javaLauncher.set(
                    project.javaToolchains.launcherFor {
                        languageVersion.set(JavaLanguageVersion.of(jdkVersion))
                    }
                )
            }
        }
        testRuns.all {
            executionTask.configure {
                // ActiveProcessorCount is used here, to make sure local setup is similar as on CI
                // Github Actions linux runners have 2 cores
                jvmArgs("-Xmx4g", "-XX:ActiveProcessorCount=2")
            }
        }
    }
}
