package tech.stackable.hbase;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseTestingUtility;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.Connection;
import org.apache.hadoop.hbase.coprocessor.RegionCoprocessor;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.util.Bytes;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestAllowAccessController extends TestUtils {
  protected static final Logger LOG = LoggerFactory.getLogger(TestAllowAccessController.class);
  protected static final HBaseTestingUtility TEST_UTIL = new HBaseTestingUtility();
  private static Configuration conf;
  private static Connection systemUserConnection;
  private static RegionCoprocessor ACCESS_CONTROLLER;

  private static User SUPERUSER;
  private static User USER_ADMIN;
  private static User USER_RW;
  private static User USER_RO;
  private static User USER_OWNER;
  private static User USER_CREATE;
  private static User USER_NONE;
  private static User USER_ADMIN_CF;

  private static final String GROUP_ADMIN = "group_admin";
  private static final String GROUP_CREATE = "group_create";
  private static final String GROUP_READ = "group_read";
  private static final String GROUP_WRITE = "group_write";

  private static User USER_GROUP_ADMIN;
  private static User USER_GROUP_CREATE;
  private static User USER_GROUP_READ;
  private static User USER_GROUP_WRITE;

  private static byte[] TEST_FAMILY = Bytes.toBytes("f1");
  private static byte[] TEST_QUALIFIER = Bytes.toBytes("q1");
  private static TableName TEST_TABLE = TableName.valueOf("testtable1");

  @Test
  // @Ignore
  public void testAllowAccessController() throws Exception {
    LOG.info("testAllowAccessController - start");

    setup(AllowAccessController.class, false, null);
    tearDown();

    LOG.info("testAllowAccessController - complete");
  }
}
