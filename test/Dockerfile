# From root folder....
#   docker build -f ./test/Dockerfile -t docker.stackable.tech/sandbox/hbase:2.6.0-stackable0.0.0-opa .
FROM docker.stackable.tech/sandbox/hbase:2.6.0-stackable0.0.0-dev

COPY  --chown=stackable:stackable target/hbase-opa-authorizer-0.1.0.jar /stackable/hbase/lib/hbase-opa-authorizer-0.1.0.jar
