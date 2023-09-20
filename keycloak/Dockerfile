FROM quay.io/keycloak/keycloak:latest as builder

    
# Enable health and metrics support
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true

# Configure a database vendor
ENV KC_DB=postgres
WORKDIR /opt/keycloak
COPY ./providers/user_attribute_mapper_custom.jar ./providers/
COPY ./providers/graalvm-js-scripting-provider-1.0-SNAPSHOT.jar ./providers/
COPY ./graalvm-jdk-20.0.2+9.1 ./graalvm-jdk
RUN export PATH=/opt/keycloak/graalvm-jdk/bin:$PATH && \
export JAVA_HOME=/opt/keycloak/graalvm-jdk
# for demonstration purposes only, please make sure to use proper certificates in production instead
RUN keytool -genkeypair -storepass password -storetype PKCS12 -keyalg RSA -keysize 2048 -dname "CN=server" -alias server -ext "SAN:c=DNS:localhost,IP:127.0.0.1" -keystore conf/server.keystore
RUN /opt/keycloak/bin/kc.sh build --features="docker,preview,scripts,token-exchange"

FROM quay.io/keycloak/keycloak:latest
COPY --from=builder /opt/keycloak/ /opt/keycloak/
# change these values to point to a running postgres instance
ENV PATH=/opt/keycloak/graalvm-jdk/bin:$PATH
ENV JAVA_HOME=/opt/keycloak/graalvm-jdk
ENV KC_DB=postgres
#ENV KC_DB_URL=<DBURL>
ENV KC_DB_URL_HOST=postgres
ENV KC_DB_URL_DATABASE=keycloak
ENV KC_DB_USERNAME=keycloak
ENV KC_DB_PASSWORD=password
ENV KC_HOSTNAME=localhost
ENV KC_HEALTH_ENABLED=true
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
