package dev.whyoleg.cryptography.algorithms

@RequiresOptIn(
    message = "These algorithms aren’t considered cryptographically secure. " +
            "They are provided only for backward compatibility with older services that require them. " +
            "For new services, avoid these algorithms.",
    level = RequiresOptIn.Level.ERROR
)
public annotation class InsecureAlgorithm
