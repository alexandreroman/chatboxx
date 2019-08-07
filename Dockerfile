# Dockerfile sample:
# you better use "Cloud Native Buildpacks" to create a secure Docker image.
#
# Go to buildpacks.io and install pack CLI.
# Then run this command to build a Docker image:
#  $ pack build myuser/myimage --publish

FROM adoptopenjdk:8-jdk-hotspot as build
WORKDIR /workspace/app

COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .
COPY src src

RUN ./mvnw -B package -DskipTests
RUN mkdir -p target/dependency && (cd target/dependency; jar -xf ../*.jar)

FROM adoptopenjdk:8-jre-hotspot
VOLUME /tmp
ARG DEPENDENCY=/workspace/app/target/dependency
COPY --from=build ${DEPENDENCY}/BOOT-INF/lib /app/lib
COPY --from=build ${DEPENDENCY}/META-INF /app/META-INF
COPY --from=build ${DEPENDENCY}/BOOT-INF/classes /app
ENTRYPOINT ["java","-noverify","-XX:TieredStopAtLevel=1","-Djava.security.egd=file:/dev/./urandom","-XX:+AlwaysPreTouch","-XX:+UnlockExperimentalVMOptions","-XX:+UseCGroupMemoryLimitForHeap","-cp","app:app/lib/*","fr.alexandreroman.chatboxx.Application"]
EXPOSE 8080
