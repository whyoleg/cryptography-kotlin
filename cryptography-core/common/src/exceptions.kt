package dev.whyoleg.cryptography

public open class CryptographyException(message: String) : Exception(message)

//TODO: name
public class NotSupportedAlgorithmException(message: String) : CryptographyException(message)
public class NotSupportedPrimitiveException(message: String) : CryptographyException(message)
