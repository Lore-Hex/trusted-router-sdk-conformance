rootProject.name = "trusted-router-java-conformance-driver"

val sdkRoot = providers.environmentVariable("TR_CONFORMANCE_SDK_ROOT").orNull
    ?: error("TR_CONFORMANCE_SDK_ROOT is required")

includeBuild(file(sdkRoot)) {
    dependencySubstitution {
        substitute(module("com.trustedrouter:trusted-router"))
            .using(project(":"))
    }
}
