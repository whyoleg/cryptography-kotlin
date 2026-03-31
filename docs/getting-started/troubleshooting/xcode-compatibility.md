# Xcode / Swift compatibility

The [CryptoKit provider](../providers/apple.md) uses Swift under the hood and requires linking against
Swift standard libraries shipped with Xcode.
The published library embeds a **hardcoded path** to these libraries:

```
/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/PLATFORM
```

This path is baked into the published cinterop klib and cannot be made dynamic at publish time.
As a result, builds fail when Xcode is **not** located at `/Applications/Xcode.app` — a common
situation when you:

- manage multiple Xcode versions with tools like [xcodes](https://github.com/XcodesOrg/xcodes),
- rename the Xcode bundle (e.g. `Xcode_16.4.app`), or
- keep Xcode on a different volume or path.

**Typical error:**

```
Could not find or use auto-linked library 'swiftCompatibilityPacks'
```

---

## Gradle plugin (recommended)

Apply the `dev.whyoleg.cryptography` Gradle plugin in the module that uses CryptoKit.
The plugin dynamically resolves the active Xcode installation at build time using `xcrun`,
so it works regardless of where Xcode is installed.

In `build.gradle.kts`, apply the plugin and enable automatic linker option configuration:

```kotlin
plugins {
    id("dev.whyoleg.cryptography") version "0.5.0"
}

cryptography {
    configureSwiftLinkerOpts = true
}
```

The plugin will automatically add the correct `-L` linker flags for every Apple target binary in
your project.

---

## Manual linker options

If you cannot use the Gradle plugin, you can add the linker options manually.

Find your Swift libraries path by running the following command and replace `/usr/bin/swift` with `/usr/lib/swift` in the output:

```bash
xcrun --find swift
# example output:
# /Applications/Xcode_16.4.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift
# → use: .../XcodeDefault.xctoolchain/usr/lib/swift
```

Add the path to every Apple binary in your `build.gradle.kts`:

```kotlin
val swiftLibsPath =
    "/Applications/Xcode_16.4.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift"

kotlin {
    listOf(
        iosArm64(),
        iosSimulatorArm64(),
        iosX64(),
        macosArm64(),
        macosX64(),
        // add other Apple targets as needed
    ).forEach { appleTarget ->
        val platformDir = when (appleTarget.konanTarget) {
            KonanTarget.IOS_ARM64  -> "iphoneos"
            KonanTarget.IOS_SIMULATOR_ARM64,
            KonanTarget.IOS_X64
                                   -> "iphonesimulator"
            KonanTarget.MACOS_ARM64,
            KonanTarget.MACOS_X64
                                   -> "macosx"
            KonanTarget.TVOS_ARM64 -> "appletvos"
            KonanTarget.TVOS_SIMULATOR_ARM64,
            KonanTarget.TVOS_X64
                                   -> "appletvsimulator"
            KonanTarget.WATCHOS_ARM32,
            KonanTarget.WATCHOS_ARM64,
            KonanTarget.WATCHOS_DEVICE_ARM64
                                   -> "watchos"
            KonanTarget.WATCHOS_SIMULATOR_ARM64,
            KonanTarget.WATCHOS_X64
                                   -> "watchsimulator"
            else                   -> error("Unsupported Apple target: ${appleTarget.konanTarget}")
        }
        appleTarget.binaries.configureEach {
            linkerOpts("-L$swiftLibsPath/$platformDir")
        }
    }
}
```
