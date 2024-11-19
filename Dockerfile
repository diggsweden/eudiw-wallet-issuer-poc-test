FROM gradle:jdk21-jammy AS gradlew-digg-builder

#ENV GRADLE_USER_HOME /home/gradle-cache

# ARG HTTP_PROXY
# ARG HTTPS_PROXY
# ARG NO_PROXY

# ENV HTTP_PROXY=$HTTP_PROXY \
#     HTTPS_PROXY=$HTTPS_PROXY \
#     NO_PROXY=$NO_PROXY \
#     http_proxy=$HTTP_PROXY \
#     https_proxy=$HTTPS_PROXY \
#     no_proxy=$NO_PROXY

#COPY ./certs/* /etc/pki/ca-trust/source/anchors/

#RUN update-ca-trust

#RUN microdnf install findutils

# add custom certs to jdk
#RUN for f in /etc/pki/ca-trust/source/anchors/* ; \
#    do keytool -importcert -cacerts -alias `echo $(basename $f)` -noprompt -file $f ; \
#done;

WORKDIR /app

#COPY gradle  /app/gradle
#COPY *.gradle gradle.* gradlew /app/
#RUN ./gradlew wrapper

#VOLUME $GRADLE_USER_HOME

############################################################################################
FROM  gradlew-digg-builder AS builder-with-project-dependencies
COPY build.gradle /app/
RUN gradle dependencies  --no-daemon

############################################################################################
FROM builder-with-project-dependencies AS builder 
COPY . . 

# should be build instead of assemble later in order to run tests
RUN gradle assemble --no-daemon

############################################################################################
FROM cgr.dev/chainguard/jre:latest-dev
COPY src/main/resources/tls.crt /usr/local/share/ca-certificates/tls.crt
USER root
RUN update-ca-certificates
RUN keytool -import -trustcacerts -file /usr/local/share/ca-certificates/tls.crt  -alias tls -cacerts -storepass changeit -noprompt
USER java
WORKDIR /app

COPY --from=builder /app/build/libs/issuer-tests-0.0.1-SNAPSHOT.jar issuer-tests-0.0.1-SNAPSHOT.jar
ENTRYPOINT ["java", "-jar", "./issuer-tests-0.0.1-SNAPSHOT.jar"]

