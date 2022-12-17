package dev.whyoleg.cryptography

public open class CryptographyException : RuntimeException {
    public constructor(message: String?) : super(message)
    public constructor(message: String?, cause: Throwable?) : super(message, cause)
    public constructor(cause: Throwable?) : super(cause)
}

public class CryptographyAlgorithmNotFoundException(
    algorithm: CryptographyAlgorithm<*>,
) : CryptographyException("Algorithm not found: $algorithm")
