import org.jetbrains.kotlin.gradle.plugin.*

fun LanguageSettingsBuilder.optInForTests() {
    optIn("kotlinx.coroutines.ExperimentalCoroutinesApi")
}
