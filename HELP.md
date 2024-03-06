# Getting Started

This is a sample project demonstrating the use of Spring Data JPA, Spring Data Rest, Springdoc with Spring Oauth2 Client Server.

## Prerequisites
Make sure to have these tools installed
* Java 17
* Docker
* Docker Compose
* Gradle
* OpenSSL

## Build & Run
Before running the application, make sure to build it. Execute the command below:
```shell
./gradlew build
```

This project uses H2 in-memory database. No need to start a database.

You will require the public key to access the API. The public key can be found in the `src/main/resources` folder in case
you want to use the public key for the resource server configuration.

Make sure the application.yaml has the proper for oauth-flow and swagger-ui.oauth  values. The default values are:
```yaml
springdoc:
  swagger-ui:
      oauth:
        client-id: nowhere-client
        client-secret: nowhere-secret
        use-pkce-with-authorization-code-grant: true
        use-basic-authentication-with-access-code-grant: true
  oauth-flow:
    authorizationUrl: http://localhost:9000/oauth2/authorize
    tokenUrl: http://localhost:9000/oauth2/token
    scopes:
      message.read: scope for read message
      message.write: scope for write message
```
These values mat with the default configuration of the authorization server, replace if needed.

Finally, start the application with the command:
```shell
./gradlew bootRun
```


## Additional Notes
The application uses Spring Data Rest to expose the JPA repositories as REST endpoints. The endpoints can be accessed via [HAL Browser](http://localhost:9001/browser/index.html#).

The application uses Springdoc to generate the Swagger documents. The documents can be accessed via [Swagger UI](http://localhost:9001/swagger-ui/index.html).

The application uses Spring Security to secure the endpoints. The application uses OAuth2 Resource Server to validate the JWT token.

The application uses Spring Data JPA to access the database. The application uses H2 in-memory database.

The application uses Spring Boot Actuator to expose the health and info endpoints. The endpoints can be accessed via [Actuator](http://localhost:9001/actuator).


### Reference Documentation

For further reference, please consider the following sections:

* [Official Gradle documentation](https://docs.gradle.org)
* [Spring Boot Gradle Plugin Reference Guide](https://docs.spring.io/spring-boot/docs/3.2.2/gradle-plugin/reference/html/)
* [Create an OCI image](https://docs.spring.io/spring-boot/docs/3.2.2/gradle-plugin/reference/html/#build-image)
* [Rest Repositories](https://docs.spring.io/spring-boot/docs/3.2.2/reference/htmlsingle/index.html#howto.data-access.exposing-spring-data-repositories-as-rest)
* [OAuth2 Resource Server](https://docs.spring.io/spring-boot/docs/3.2.2/reference/htmlsingle/index.html#web.security.oauth2.server)
* [Spring Boot Actuator](https://docs.spring.io/spring-boot/docs/3.2.2/reference/htmlsingle/index.html#actuator)
* [Spring Data JPA](https://docs.spring.io/spring-boot/docs/3.2.2/reference/htmlsingle/index.html#data.sql.jpa-and-spring-data)
* [Spring Web](https://docs.spring.io/spring-boot/docs/3.2.2/reference/htmlsingle/index.html#web)

### Guides

The following guides illustrate how to use some features concretely:

* [Accessing JPA Data with REST](https://spring.io/guides/gs/accessing-data-rest/)
* [Accessing Neo4j Data with REST](https://spring.io/guides/gs/accessing-neo4j-data-rest/)
* [Accessing MongoDB Data with REST](https://spring.io/guides/gs/accessing-mongodb-data-rest/)
* [Building a RESTful Web Service with Spring Boot Actuator](https://spring.io/guides/gs/actuator-service/)
* [Accessing Data with JPA](https://spring.io/guides/gs/accessing-data-jpa/)
* [Building a RESTful Web Service](https://spring.io/guides/gs/rest-service/)
* [Serving Web Content with Spring MVC](https://spring.io/guides/gs/serving-web-content/)
* [Building REST services with Spring](https://spring.io/guides/tutorials/rest/)

### Additional Links

These additional references should also help you:

* [Gradle Build Scans – insights for your project's build](https://scans.gradle.com#gradle)

