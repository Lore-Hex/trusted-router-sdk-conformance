plugins {
    application
}

repositories {
    mavenCentral()
}

dependencies {
    // Replaced by settings.gradle.kts with the checkout named by
    // TR_CONFORMANCE_SDK_ROOT. The version is deliberately not a release tag:
    // conformance must execute the working tree, not a published artifact.
    implementation("com.trustedrouter:trusted-router:conformance-checkout")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(8)
    options.encoding = "UTF-8"
}

application {
    mainClass.set("com.trustedrouter.conformance.Driver")
}

providers.gradleProperty("trConformanceBuildDir").orNull?.let {
    layout.buildDirectory.set(file(it))
}
