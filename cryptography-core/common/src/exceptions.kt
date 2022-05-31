package dev.whyoleg.cryptography

public open class CryptographyException(message: String) : Exception(message)

public class NotSupportedAlgorithmException(message: String) : CryptographyException(message)
