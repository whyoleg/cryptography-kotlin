package dev.whyoleg.cryptography

public open class CryptographyException : RuntimeException {
    public constructor(message: String?) : super(message)
    public constructor(message: String?, cause: Throwable?) : super(message, cause)
    public constructor(cause: Throwable?) : super(cause)
}

public class CryptographyAlgorithmNotFoundException(
    algorithm: CryptographyAlgorithmIdentifier<*>,
) : CryptographyException("Algorithm not found: $algorithm")

public class CryptographyOperationNotSupportedException(
    message: String?,
) : CryptographyException(message)
