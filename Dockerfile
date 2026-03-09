# Stage 1: build the extension JAR
FROM maven:3.9-eclipse-temurin-17-alpine AS builder
WORKDIR /build
COPY pom.xml .
RUN mvn dependency:go-offline -q
COPY src/ src/
RUN mvn package -q -DskipTests

# Stage 2: Keycloak with the extension pre-loaded
FROM quay.io/keycloak/keycloak:24.0.4
COPY --from=builder /build/target/group-password-policy-*.jar /opt/keycloak/providers/

ENV KC_HEALTH_ENABLED=true

ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start-dev"]
