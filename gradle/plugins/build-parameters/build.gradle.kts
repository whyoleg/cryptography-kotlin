plugins {
    id("org.gradlex.build-parameters") version "1.3"
}

buildParameters {
    group("testsuite") {
        enumeration("step") {
            description.set("Define which test step to execute")
            values.addAll(
                "GenerateTestStep",
                "ComputeTestStep",
                "ValidateTestStep",
            )
        }
    }
}
