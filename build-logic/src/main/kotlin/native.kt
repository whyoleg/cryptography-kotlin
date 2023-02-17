import org.jetbrains.kotlin.gradle.dsl.*
import org.jetbrains.kotlin.gradle.plugin.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.konan.target.*

fun KotlinNativeTargetWithTests<*>.setupTests() {
    //setup additional running in RELEASE move for Native targets
    binaries.test(listOf(NativeBuildType.RELEASE))
    testRuns.create("releaseTest") {
        setExecutionSourceFrom(binaries.getTest(NativeBuildType.RELEASE))
    }
    //don't even link tests if we can't run them (like, linux on macos, or mingw on linux/macos, etc)
    testRuns.all {
        executionSource.binary.linkTaskProvider.get().enabled = (this as ExecutionTaskHolder<*>).executionTask.get().enabled
    }
}

//should be called after targets registration, will be replaced with hierarchy with kotlin 1.8.20
fun KotlinMultiplatformExtension.setupSharedNativeSourceSets() {
    sharedSourceSet("native") { it is KotlinNativeTarget }
    sharedSourceSet("mingw") { (it as? KotlinNativeTarget)?.konanTarget?.family == Family.MINGW }
    sharedSourceSet("linux") { (it as? KotlinNativeTarget)?.konanTarget?.family == Family.LINUX }
    sharedSourceSet("darwin") { (it as? KotlinNativeTarget)?.konanTarget?.family?.isAppleFamily == true }
}
