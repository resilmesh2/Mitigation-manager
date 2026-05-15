FROM docker.io/library/clojure:temurin-25-lein AS builder

WORKDIR /usr

COPY project.clj .
RUN --mount=type=cache,target=/root/.m2 lein deps

COPY src src
RUN --mount=type=cache,target=/root/.m2 lein uberjar

FROM docker.io/library/eclipse-temurin:25-jdk
LABEL org.opencontainers.image.authors="Ekam Puri Nieto <ekam.purin@um.es>"

WORKDIR /usr

COPY --from=builder /usr/target/uberjar/*-standalone.jar app.jar

COPY config.edn .
COPY data data

ENTRYPOINT [ "java", "-jar", "app.jar" ]
