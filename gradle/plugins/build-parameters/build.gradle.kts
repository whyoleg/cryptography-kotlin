/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("org.gradlex.build-parameters") version "1.4.3"
}

group = "cryptography.build"

buildParameters {
    enableValidation.set(false)
    string("version")
    bool("ci") {
        fromEnvironment()
        defaultValue.set(false)
    }
    group("testtool") {
        string("instanceId") {
            description.set("Instance ID for running tests")
        }
    }
    group("tests") {
        group("compatibility") {
            enumeration("step") {
                description.set("Define which test step to execute (if InMemory - will run all steps without server)")
                defaultValue.set("InMemory")
                values.addAll("InMemory", "Generate", "Validate")
            }
        }
    }
    string("useKotlin")
    group("skip") {
        bool("test") {
            description.set("Skip running tests")
            defaultValue.set(false)
        }
        bool("link") {
            description.set("Skip linking native tests")
            defaultValue.set(false)
        }
    }
}
