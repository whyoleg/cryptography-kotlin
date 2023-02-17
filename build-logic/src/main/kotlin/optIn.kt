import org.jetbrains.kotlin.gradle.plugin.*

fun LanguageSettingsBuilder.optInForTests() {
    optIn("kotlinx.coroutines.ExperimentalCoroutinesApi")
    optIn("dev.whyoleg.cryptography.provider.CryptographyProviderApi")
    optIn("dev.whyoleg.cryptography.algorithms.InsecureAlgorithm")
}
