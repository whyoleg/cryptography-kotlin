plugins {
    id("org.gradlex.build-parameters") version "1.4.2"
}

buildParameters {
    bool("ci") {
        fromEnvironment()
        defaultValue.set(false)
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
    group("kotlin") {
        group("override") {
            string("version") {
                description.set("Override Kotlin version")
            }
        }
    }
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