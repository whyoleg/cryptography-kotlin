package dev.whyoleg.cryptography.jdk

import java.security.*

public sealed class JdkProvider {
    public object Default : JdkProvider()
    public class Instance(public val provider: Provider) : JdkProvider()
    public class Name(public val provider: String) : JdkProvider()
}
