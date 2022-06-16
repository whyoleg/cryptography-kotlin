package dev.whyoleg.cryptography

//implementation in core
public interface AlgorithmParameters

//interface in core, implementation in provider: store some information, can't perform operations
public interface CryptographyMaterial {
    public val parameters: AlgorithmParameters
}

//interface in core, implementation in provider: perform some operations
public interface CryptographyPrimitive {
    public val parameters: AlgorithmParameters
}

public object EmptyMaterial : CryptographyMaterial {
    override val parameters: AlgorithmParameters get() = TODO("")//EmptyParameters
}

