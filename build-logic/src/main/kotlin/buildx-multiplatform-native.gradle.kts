import org.jetbrains.kotlin.gradle.plugin.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*

plugins {
    id("buildx-multiplatform")
}

kotlin {
    targets.all {
        if (this is KotlinNativeTargetWithTests<*>) {
            //setup tests running in RELEASE mode
            binaries.test(listOf(NativeBuildType.RELEASE))
            testRuns.create("releaseTest") {
                setExecutionSourceFrom(binaries.getTest(NativeBuildType.RELEASE))
            }
            //don't even link tests if we can't run them (like, linux on macos, or mingw on linux/macos, etc)
            testRuns.all {
                executionSource.binary.linkTaskProvider.get().enabled = (this as ExecutionTaskHolder<*>).executionTask.get().enabled
            }
        }
    }
}
