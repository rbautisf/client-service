plugins {
    application
    java
    id("org.springframework.boot") version "3.2.4"
    id("io.spring.dependency-management") version "1.1.4"
}

group = "com.nowherelearn"
version = "0.0.1-SNAPSHOT"

java {
    sourceCompatibility = JavaVersion.VERSION_21
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.5.0")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("com.h2database:h2")
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-data-rest")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-client")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    implementation("org.springframework:spring-webflux")
    implementation("io.projectreactor.netty:reactor-netty")
    implementation("org.webjars:webjars-locator-core")
    implementation("org.webjars:bootstrap:5.3.3")
    implementation("org.webjars:popper.js:2.9.3")
    implementation("org.webjars:jquery:3.6.4")
}

application {
    // Define the main class for the application.
    mainClass = "com.nowherelearn.clientservice.ClientServiceApplication"
}

tasks.withType<Test> {
    useJUnitPlatform()
}

