FROM quay.io/keycloak/keycloak:latest as builder
   
# Enable health and metrics support
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true

# Configure a database vendor
ENV KC_DB=postgres
WORKDIR /opt/keycloak
COPY ./providers/user_attribute_mapper_custom.jar ./providers/
COPY ./aduneo-realm.json ./data/import/aduneo-realm.json
# for demonstration purposes only, please make sure to use proper certificates in production instead
RUN keytool -genkeypair -storepass password -storetype PKCS12 -keyalg RSA -keysize 2048 -dname "CN=server" -alias server -ext "SAN:c=DNS:localhost,IP:127.0.0.1" -keystore conf/server.keystore
RUN ./bin/kc.sh build --features="docker,preview,scripts,token-exchange"

FROM quay.io/keycloak/keycloak:latest
COPY --from=builder /opt/keycloak/ /opt/keycloak/

ENV KC_DB=postgres
ENV KC_DB_URL_HOST=postgres
ENV KC_DB_URL_DATABASE=keycloak
ENV KC_DB_USERNAME=keycloak
ENV KC_DB_PASSWORD=password
ENV KC_HOSTNAME=localhost
ENV KC_HEALTH_ENABLED=true
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
