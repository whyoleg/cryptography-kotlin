# Style note: prefer just's inline if/else and built-in functions (e.g. trim_start_matches) over
# shell scripting in recipes, so that the resolved command is always printed to the user.

# Show available commands
default:
    @just --list

# Build all modules (skip tests and native linking); optionally build a specific module:
#   just build core               -> builds :cryptography-core
#   just build :cryptography-core -> passes exact Gradle module path
build module="":
    ./gradlew {{ if module == "" { "build" } else if module != trim_start_matches(module, ":") { module + ":build" } else { ":cryptography-" + module + ":build" } }} -Pckbuild.skipTestTasks=true -Pckbuild.skipLinkTasks=true --continue

# Link all native binaries
link:
    ./gradlew linkAll --continue

# Update the public API ABI dump after API changes
update-abi:
    ./gradlew updateKotlinAbi --continue

# Generate API docs and build MkDocs site
docs:
    ./gradlew :mkdocsPrepare
    mkdocs build --clean --strict

# Remove compatibility test server storage (run before a fresh generate+validate cycle)
compat-clean:
    rm -rf build/testtool/server-storage

# Run JDK (JVM) tests; filter by class (e.g. "*AesGcm*"), or add --step=generate/validate/loop for compat testing
[arg("step", long="step", help="Compatibility step to run (generate,validate,loop)")]
test-provider-jdk filter="" step="":
    ./gradlew :cryptography-provider-jdk:jvmTest{{ if step != "" { " --continue -Pckbuild.providerTests.step=compatibility." + step + if step != "loop" { " -Pckbuild.testtool.enabled=true" } else { "" } } else { "" } }}{{ if filter != "" { " --tests " + filter } else { "" } }}

# Run WebCrypto (WasmJS on Node.js) tests; filter by class, or add --step=generate/validate/loop for compat testing
[arg("step", long="step", help="Compatibility step to run (generate,validate,loop)")]
test-provider-webcrypto filter="" step="":
    ./gradlew :cryptography-provider-webcrypto:wasmJsNodeTest{{ if step != "" { " --continue -Pckbuild.providerTests.step=compatibility." + step + if step != "loop" { " -Pckbuild.testtool.enabled=true" } else { "" } } else { "" } }}{{ if filter != "" { " --tests " + filter } else { "" } }}

# Run Apple CommonCrypto tests; filter by class, or add --step=generate/validate/loop for compat testing
[arg("step", long="step", help="Compatibility step to run (generate,validate,loop)")]
test-provider-apple filter="" step="":
    ./gradlew :cryptography-provider-apple:macosArm64Test{{ if step != "" { " --continue -Pckbuild.providerTests.step=compatibility." + step + if step != "loop" { " -Pckbuild.testtool.enabled=true" } else { "" } } else { "" } }}{{ if filter != "" { " --tests " + filter } else { "" } }}

# Run Apple CryptoKit tests; filter by class, or add --step=generate/validate/loop for compat testing
[arg("step", long="step", help="Compatibility step to run (generate,validate,loop)")]
test-provider-cryptokit filter="" step="":
    ./gradlew :cryptography-provider-cryptokit:macosArm64Test{{ if step != "" { " --continue -Pckbuild.providerTests.step=compatibility." + step + if step != "loop" { " -Pckbuild.testtool.enabled=true" } else { "" } } else { "" } }}{{ if filter != "" { " --tests " + filter } else { "" } }}

# Run OpenSSL3 prebuilt tests; filter by class, or add --step=generate/validate/loop for compat testing
[arg("step", long="step", help="Compatibility step to run (generate,validate,loop)")]
test-provider-openssl3 filter="" step="":
    ./gradlew :cryptography-provider-openssl3-prebuilt:macosArm64Test{{ if step != "" { " --continue -Pckbuild.providerTests.step=compatibility." + step + if step != "loop" { " -Pckbuild.testtool.enabled=true" } else { "" } } else { "" } }}{{ if filter != "" { " --tests " + filter } else { "" } }}
