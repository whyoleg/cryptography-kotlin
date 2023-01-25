import org.gradle.jvm.toolchain.*
import org.gradle.kotlin.dsl.*
import org.jetbrains.kotlin.gradle.targets.jvm.*

fun KotlinJvmTarget.setupTests() {
    //setup additional testing on different JDK versions (default task jvmTest will run on JDK8)
    listOf(11, 17).forEach { jdkVersion ->
        testRuns.create("${jdkVersion}Test") {
            executionTask.configure {
                javaLauncher.set(
                    //project.javaToolchains //need Gradle 8
                    project.extensions.getByType<JavaToolchainService>().launcherFor {
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
