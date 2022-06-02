package dev.whyoleg.cryptography.key

import dev.whyoleg.vio.*

//TODO: decide on export operation

public interface KeyOperation<P, I, O> {
    public operator fun invoke(parameters: P, input: I): O
}

// marker interface for getting key
public interface KeyFactoryOperation<P, I, K : Key> : KeyOperation<P, I, K>

//generates new key from parameters
public interface KeyGenerateOperation<P, K : Key> : KeyFactoryOperation<P, Unit, K>

//create key instance from some parameters that are already generated
public interface KeyCreateOperation<P, K : Key> : KeyFactoryOperation<P, Unit, K>

//export and import of keys to some external storage: bytes, files, etc.
public interface KeyImportOperation<P, K : Key> : KeyFactoryOperation<P, KeyStore, K>
public interface KeyExportOperation<P, R> : KeyOperation<P, KeyStore, R>

//derive key from password or other key - TODO: separate interface for password and other key?
public interface KeyDeriveOperation<P, I, K : Key> : KeyFactoryOperation<P, I, K>
public interface KeyPasswordDeriveOperation<P, K : Key> : KeyDeriveOperation<P, BufferView, K>

//TODO: better name
public interface KeyMasterKeyDeriveOperation<P, MK : Key, K : Key> : KeyDeriveOperation<P, MK, K>

//TODO: key agreement/exchange operation interface
