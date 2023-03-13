import org.jetbrains.kotlin.gradle.plugin.mpp.*

fun KotlinNativeTarget.cinterop(
    defFileName: String,
    groupName: String = "common",
    compilationName: String = "main",
    block: DefaultCInteropSettings.() -> Unit = {},
) {
    compilations.getByName(compilationName) {
        cinterops.create(defFileName) {
            // replace capitalize after Gradle 8
            defFile("src/${groupName}${compilationName.capitalize()}/cinterop/$defFileName.def")
            block()
        }
    }
}
