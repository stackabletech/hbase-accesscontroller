package tech.stackable.hbase;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.apache.hadoop.hbase.HConstants;
import org.apache.hadoop.hbase.client.Connection;
import org.apache.hadoop.hbase.client.ConnectionFactory;
import org.apache.hadoop.hbase.security.access.AccessControlClient;
import org.apache.hadoop.hbase.util.Bytes;
import org.junit.Test;

public class TestAllowAccessController extends TestUtils {

  private static byte[] TEST_FAMILY = Bytes.toBytes("f1");

  @Test
  public void testAllowAccessController() throws Exception {
    LOG.info("testAllowAccessController - start");

    setup(AllowAccessController.class, false, "xxx");
    tearDown();

    LOG.info("testAllowAccessController - complete");
  }

  @Test
  public void testGetUserPermissions() throws Throwable {
    setup(AllowAccessController.class, false, "xxx");

    Connection conn = null;
    try {
      conn = ConnectionFactory.createConnection(conf);

      try {
        // test case with table name as null
        assertEquals(3, AccessControlClient.getUserPermissions(conn, null, TEST_FAMILY).size());
        fail("this should have thrown IllegalArgumentException");
      } catch (IllegalArgumentException ex) {
        // expected
      }
      try {
        // test case with table name as emplty
        assertEquals(
            3,
            AccessControlClient.getUserPermissions(conn, HConstants.EMPTY_STRING, TEST_FAMILY)
                .size());
        fail("this should have thrown IllegalArgumentException");
      } catch (IllegalArgumentException ex) {
        // expected
      }
      try {
        // test case with table name as namespace name
        assertEquals(3, AccessControlClient.getUserPermissions(conn, "@xxx", TEST_FAMILY).size());
        fail("this should have thrown IllegalArgumentException");
      } catch (IllegalArgumentException ex) {
        // expected
      }
    } finally {
      if (conn != null) {
        conn.close();
      }
    }
    tearDown();
  }
}
