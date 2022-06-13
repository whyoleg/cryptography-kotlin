package dev.whyoleg.cryptography.key

import dev.whyoleg.vio.*
import kotlin.jvm.*

//TODO: better name?
@JvmInline
public value class BinaryKey(public val value: BufferView)

//keyChain - what is it

//binary keyRepresentation: RAW, JWK, DER, PEM, etc + File, buffer
//code keyMaterial: Secret, RSA public/private key, ECDSA public/private key, etc
//key algorithm parameters: Secret (length), RSA (public exponent, size), RSA HASH(PE, ML, HASH parameters)
//

//exportable key, material, parameters

public interface KeyPrimitive<
        Parameters : KeyParameters,
        Material : KeyMaterial,
        Representation : KeyRepresentation
        >

public fun <Parameters: KeyParameters> KeyPrimitive<Parameters, *, *>.parameterized(): Boolean {

}

public interface ParameterizedKey<Parameters : KeyParameters> {
    public val parameters: Parameters
}

public interface MaterializedKey<Material : KeyMaterial> {
    public val material: Material
}

public sealed interface ExportableKey {
    public interface Sync : ExportableKey {
        public fun export(representation: KeyRepresentation, destination: KeyView)
    }

    public interface Async : ExportableKey {
        public suspend fun export(representation: KeyRepresentation, destination: KeyView)
    }
}

public interface KeyMaterial

public interface KeyParameters

public interface SymmetricKey : Key


public sealed interface KeyRepresentation {
    public object RAW
    public object DER
    public object JWK
}

public sealed interface KeyView {
    public class Buffer(public val value: BufferView) : KeyView
    public class File(public val value: PathView) : KeyView
}
