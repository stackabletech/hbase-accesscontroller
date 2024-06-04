#
#   docker build -t docker.stackable.tech/sandbox/hbase:2.6.0-stackable0.0.0-opa .
#
FROM docker.stackable.tech/sandbox/hbase:2.6.0-stackable0.0.0-dev

COPY  --chown=stackable:stackable target/hbase-opa-authorizer-0.1.0.jar /stackable/hbase-2.6.0/lib/hbase-opa-authorizer-0.1.0.jar