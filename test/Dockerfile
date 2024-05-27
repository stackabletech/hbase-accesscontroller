# From root folder....
# docker build -f ./test/Dockerfile -t docker.stackable.tech/stackable/hbase:2.4.17-stackable0.0.0-dev-opa

FROM docker.stackable.tech/stackable/hbase:2.4.17-stackable0.0.0-dev

RUN rm -rf /stackable/hbase/lib/hbase-opa-authorizer-*.jar
COPY --chown=stackable:stackable ./target/hbase-opa-authorizer-*.jar /stackable/hbase/lib/
