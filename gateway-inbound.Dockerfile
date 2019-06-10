FROM asecurityteam/serverfull-gateway
COPY api-inbound.yaml .
ENV TRANSPORTD_OPENAPI_SPECIFICATION_FILE="api-inbound.yaml"
