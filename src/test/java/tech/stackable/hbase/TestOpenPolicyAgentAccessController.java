package tech.stackable.hbase;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.apache.hadoop.hbase.AuthUtil.toGroupEntry;
import static org.apache.hadoop.hbase.security.access.SecureTestUtil.*;
import static org.junit.Assert.*;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.google.protobuf.BlockingRpcChannel;
import java.util.Arrays;
import java.util.Collection;
import org.apache.hadoop.hbase.*;
import org.apache.hadoop.hbase.client.*;
import org.apache.hadoop.hbase.protobuf.generated.AccessControlProtos;
import org.apache.hadoop.hbase.security.Superusers;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.access.*;
import org.apache.hadoop.hbase.util.Bytes;
import org.junit.Rule;
import org.junit.Test;

public class TestOpenPolicyAgentAccessController extends TestUtils {
  public static final String OPA_URL = "http://localhost:8089";

  @Rule public WireMockRule wireMockRule = new WireMockRule(8089);

  @Test
  public void testOpenPolicyAgentAccessControllerPrePut() throws Exception {
    LOG.info("testOpenPolicyAgentAccessController - start");

    stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));

    setup(OpenPolicyAgentAccessController.class, false, OPA_URL);

    HTableDescriptor htd = new HTableDescriptor(TEST_TABLE);
    HColumnDescriptor hcd = new HColumnDescriptor(TEST_FAMILY);
    hcd.setMaxVersions(100);
    htd.addFamily(hcd);
    htd.setOwner(USER_OWNER);

    createTable(TEST_UTIL, TEST_UTIL.getAdmin(), htd, new byte[][] {Bytes.toBytes("s")});
    deleteTable(TEST_UTIL, TEST_TABLE);

    tearDown();
    LOG.info("testOpenPolicyAgentAccessController - complete");
  }

  @Test
  public void testDefaultAccessControllerGetUserPermissions() throws Throwable {
    setup(AccessController.class, true, null);
    setUpTables();

    Connection conn = null;
    try {
      conn = ConnectionFactory.createConnection(conf);
      User nSUser1 = User.createUserForTesting(conf, "nsuser1", new String[0]);
      User nSUser2 = User.createUserForTesting(conf, "nsuser2", new String[0]);
      User nSUser3 = User.createUserForTesting(conf, "nsuser3", new String[0]);

      // Global access groups
      User globalGroupUser1 =
          User.createUserForTesting(conf, "globalGroupUser1", new String[] {"group_admin"});
      User globalGroupUser2 =
          User.createUserForTesting(
              conf, "globalGroupUser2", new String[] {"group_admin", "group_create"});
      // Namespace access groups
      User nsGroupUser1 =
          User.createUserForTesting(conf, "nsGroupUser1", new String[] {"ns_group1"});
      User nsGroupUser2 =
          User.createUserForTesting(conf, "nsGroupUser2", new String[] {"ns_group2"});
      // table Access groups
      User tableGroupUser1 =
          User.createUserForTesting(conf, "tableGroupUser1", new String[] {"table_group1"});
      User tableGroupUser2 =
          User.createUserForTesting(conf, "tableGroupUser2", new String[] {"table_group2"});

      // Create namespaces
      String nsPrefix = "testNS";
      final String namespace1 = nsPrefix + "1";
      NamespaceDescriptor desc1 = NamespaceDescriptor.create(namespace1).build();
      createNamespace(TEST_UTIL, desc1);
      String namespace2 = nsPrefix + "2";
      NamespaceDescriptor desc2 = NamespaceDescriptor.create(namespace2).build();
      createNamespace(TEST_UTIL, desc2);

      // Grant namespace permission
      grantOnNamespace(TEST_UTIL, nSUser1.getShortName(), namespace1, Permission.Action.ADMIN);
      grantOnNamespace(TEST_UTIL, nSUser3.getShortName(), namespace1, Permission.Action.READ);
      grantOnNamespace(TEST_UTIL, toGroupEntry("ns_group1"), namespace1, Permission.Action.ADMIN);
      grantOnNamespace(TEST_UTIL, nSUser2.getShortName(), namespace2, Permission.Action.ADMIN);
      grantOnNamespace(TEST_UTIL, nSUser3.getShortName(), namespace2, Permission.Action.ADMIN);
      grantOnNamespace(
          TEST_UTIL,
          toGroupEntry("ns_group2"),
          namespace2,
          Permission.Action.READ,
          Permission.Action.WRITE);

      // Create tables
      TableName table1 = TableName.valueOf(namespace1 + TableName.NAMESPACE_DELIM + "t1");
      TableName table2 = TableName.valueOf(namespace2 + TableName.NAMESPACE_DELIM + "t2");
      byte[] TEST_FAMILY2 = Bytes.toBytes("f2");
      byte[] TEST_QUALIFIER2 = Bytes.toBytes("q2");
      createTestTable(table1, TEST_FAMILY);
      createTestTable(table2, TEST_FAMILY2);

      // Grant table permissions
      grantOnTable(
          TEST_UTIL, toGroupEntry("table_group1"), table1, null, null, Permission.Action.ADMIN);
      grantOnTable(
          TEST_UTIL, USER_ADMIN.getShortName(), table1, null, null, Permission.Action.ADMIN);
      grantOnTable(
          TEST_UTIL,
          USER_ADMIN_CF.getShortName(),
          table1,
          TEST_FAMILY,
          null,
          Permission.Action.ADMIN);
      grantOnTable(
          TEST_UTIL,
          USER_RW.getShortName(),
          table1,
          TEST_FAMILY,
          TEST_QUALIFIER,
          Permission.Action.READ);
      grantOnTable(
          TEST_UTIL,
          USER_RW.getShortName(),
          table1,
          TEST_FAMILY,
          TEST_QUALIFIER2,
          Permission.Action.WRITE);

      grantOnTable(
          TEST_UTIL, toGroupEntry("table_group2"), table2, null, null, Permission.Action.ADMIN);
      grantOnTable(
          TEST_UTIL, USER_ADMIN.getShortName(), table2, null, null, Permission.Action.ADMIN);
      grantOnTable(
          TEST_UTIL,
          USER_ADMIN_CF.getShortName(),
          table2,
          TEST_FAMILY2,
          null,
          Permission.Action.ADMIN);
      grantOnTable(
          TEST_UTIL,
          USER_RW.getShortName(),
          table2,
          TEST_FAMILY2,
          TEST_QUALIFIER,
          Permission.Action.READ);
      grantOnTable(
          TEST_UTIL,
          USER_RW.getShortName(),
          table2,
          TEST_FAMILY2,
          TEST_QUALIFIER2,
          Permission.Action.WRITE);

      Collection<String> superUsers = Superusers.getSuperUsers();
      int superUserCount = superUsers.size();

      // Global User ACL
      validateGlobalUserACLForGetUserPermissions(
          conn, nSUser1, globalGroupUser1, globalGroupUser2, superUsers, superUserCount);

      // Namespace ACL
      validateNamespaceUserACLForGetUserPermissions(
          conn, nSUser1, nSUser3, nsGroupUser1, nsGroupUser2, nsPrefix, namespace1, namespace2);

      // Table + Users
      validateTableACLForGetUserPermissions(
          conn,
          nSUser1,
          tableGroupUser1,
          tableGroupUser2,
          nsPrefix,
          table1,
          table2,
          TEST_QUALIFIER2,
          superUsers);

      // exception scenarios

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
        assertEquals(
            3, AccessControlClient.getUserPermissions(conn, "@" + namespace2, TEST_FAMILY).size());
        fail("this should have thrown IllegalArgumentException");
      } catch (IllegalArgumentException ex) {
        // expected
      }

      // Clean the table and namespace
      deleteTable(TEST_UTIL, table1);
      deleteTable(TEST_UTIL, table2);
      deleteNamespace(TEST_UTIL, namespace1);
      deleteNamespace(TEST_UTIL, namespace2);
    } finally {
      if (conn != null) {
        conn.close();
      }
    }
    cleanUpTables();
    tearDown();
  }

  @Test
  public void testDefaultAccessControllerHasPermission() throws Throwable {
    setup(AccessController.class, true, null);
    setUpTables();

    Connection conn = null;
    try {
      conn = ConnectionFactory.createConnection(conf);
      // Create user and set namespace ACL
      User user1 = User.createUserForTesting(conf, "testHasPermissionUser1", new String[0]);
      // Grant namespace permission
      grantOnNamespaceUsingAccessControlClient(
          TEST_UTIL,
          conn,
          user1.getShortName(),
          NamespaceDescriptor.DEFAULT_NAMESPACE.getName(),
          Permission.Action.ADMIN,
          Permission.Action.CREATE,
          Permission.Action.READ);

      // Create user and set table ACL
      User user2 = User.createUserForTesting(conf, "testHasPermissionUser2", new String[0]);
      // Grant namespace permission
      grantOnTableUsingAccessControlClient(
          TEST_UTIL,
          conn,
          user2.getShortName(),
          TEST_TABLE,
          TEST_FAMILY,
          TEST_QUALIFIER,
          Permission.Action.READ,
          Permission.Action.WRITE);

      // Verify action privilege
      AccessTestAction hasPermissionActionCP =
          new AccessTestAction() {
            @Override
            public Object run() throws Exception {
              try (Connection conn = ConnectionFactory.createConnection(conf);
                  Table acl = conn.getTable(PermissionStorage.ACL_TABLE_NAME)) {
                BlockingRpcChannel service = acl.coprocessorService(TEST_TABLE.getName());
                AccessControlProtos.AccessControlService.BlockingInterface protocol =
                    AccessControlProtos.AccessControlService.newBlockingStub(service);
                Permission.Action[] actions = {Permission.Action.READ, Permission.Action.WRITE};
                AccessControlUtil.hasPermission(
                    null,
                    protocol,
                    TEST_TABLE,
                    TEST_FAMILY,
                    HConstants.EMPTY_BYTE_ARRAY,
                    "dummy",
                    actions);
              }
              return null;
            }
          };
      AccessTestAction hasPermissionAction =
          new AccessTestAction() {
            @Override
            public Object run() throws Exception {
              try (Connection conn = ConnectionFactory.createConnection(conf)) {
                Permission.Action[] actions = {Permission.Action.READ, Permission.Action.WRITE};
                conn.getAdmin()
                    .hasUserPermissions(
                        "dummy",
                        Arrays.asList(
                            Permission.newBuilder(TEST_TABLE)
                                .withFamily(TEST_FAMILY)
                                .withQualifier(HConstants.EMPTY_BYTE_ARRAY)
                                .withActions(actions)
                                .build()));
              }
              return null;
            }
          };
      verifyAllowed(
          hasPermissionActionCP,
          SUPERUSER,
          USER_ADMIN,
          USER_GROUP_ADMIN,
          USER_OWNER,
          USER_ADMIN_CF,
          user1);
      verifyDenied(hasPermissionActionCP, USER_CREATE, USER_RW, USER_RO, USER_NONE, user2);
      verifyAllowed(
          hasPermissionAction,
          SUPERUSER,
          USER_ADMIN,
          USER_GROUP_ADMIN,
          USER_OWNER,
          USER_ADMIN_CF,
          user1);
      verifyDenied(hasPermissionAction, USER_CREATE, USER_RW, USER_RO, USER_NONE, user2);

      // Check for global user
      assertTrue(
          AccessControlClient.hasPermission(
              conn,
              TEST_TABLE.getNameAsString(),
              HConstants.EMPTY_BYTE_ARRAY,
              HConstants.EMPTY_BYTE_ARRAY,
              USER_ADMIN.getShortName(),
              Permission.Action.READ,
              Permission.Action.WRITE,
              Permission.Action.CREATE,
              Permission.Action.ADMIN));
      assertFalse(
          AccessControlClient.hasPermission(
              conn,
              TEST_TABLE.getNameAsString(),
              HConstants.EMPTY_BYTE_ARRAY,
              HConstants.EMPTY_BYTE_ARRAY,
              USER_ADMIN.getShortName(),
              Permission.Action.READ,
              Permission.Action.WRITE,
              Permission.Action.CREATE,
              Permission.Action.ADMIN,
              Permission.Action.EXEC));

      // Check for namespace access user
      assertTrue(
          AccessControlClient.hasPermission(
              conn,
              TEST_TABLE.getNameAsString(),
              HConstants.EMPTY_BYTE_ARRAY,
              HConstants.EMPTY_BYTE_ARRAY,
              user1.getShortName(),
              Permission.Action.ADMIN,
              Permission.Action.CREATE));
      assertFalse(
          AccessControlClient.hasPermission(
              conn,
              TEST_TABLE.getNameAsString(),
              HConstants.EMPTY_BYTE_ARRAY,
              HConstants.EMPTY_BYTE_ARRAY,
              user1.getShortName(),
              Permission.Action.ADMIN,
              Permission.Action.READ,
              Permission.Action.EXEC));

      // Check for table owner
      assertTrue(
          AccessControlClient.hasPermission(
              conn,
              TEST_TABLE.getNameAsString(),
              HConstants.EMPTY_BYTE_ARRAY,
              HConstants.EMPTY_BYTE_ARRAY,
              USER_OWNER.getShortName(),
              Permission.Action.READ,
              Permission.Action.WRITE,
              Permission.Action.EXEC,
              Permission.Action.CREATE,
              Permission.Action.ADMIN));

      // Check for table user
      assertTrue(
          AccessControlClient.hasPermission(
              conn,
              TEST_TABLE.getNameAsString(),
              HConstants.EMPTY_BYTE_ARRAY,
              HConstants.EMPTY_BYTE_ARRAY,
              USER_CREATE.getShortName(),
              Permission.Action.READ,
              Permission.Action.WRITE));
      assertFalse(
          AccessControlClient.hasPermission(
              conn,
              TEST_TABLE.getNameAsString(),
              HConstants.EMPTY_BYTE_ARRAY,
              HConstants.EMPTY_BYTE_ARRAY,
              USER_RO.getShortName(),
              Permission.Action.READ,
              Permission.Action.WRITE));

      // Check for family access user
      assertTrue(
          AccessControlClient.hasPermission(
              conn,
              TEST_TABLE.getNameAsString(),
              TEST_FAMILY,
              HConstants.EMPTY_BYTE_ARRAY,
              USER_RO.getShortName(),
              Permission.Action.READ));
      assertTrue(
          AccessControlClient.hasPermission(
              conn,
              TEST_TABLE.getNameAsString(),
              TEST_FAMILY,
              HConstants.EMPTY_BYTE_ARRAY,
              USER_RW.getShortName(),
              Permission.Action.READ,
              Permission.Action.WRITE));
      assertFalse(
          AccessControlClient.hasPermission(
              conn,
              TEST_TABLE.getNameAsString(),
              HConstants.EMPTY_BYTE_ARRAY,
              HConstants.EMPTY_BYTE_ARRAY,
              USER_ADMIN_CF.getShortName(),
              Permission.Action.ADMIN,
              Permission.Action.CREATE));
      assertTrue(
          AccessControlClient.hasPermission(
              conn,
              TEST_TABLE.getNameAsString(),
              TEST_FAMILY,
              HConstants.EMPTY_BYTE_ARRAY,
              USER_ADMIN_CF.getShortName(),
              Permission.Action.ADMIN,
              Permission.Action.CREATE));
      assertFalse(
          AccessControlClient.hasPermission(
              conn,
              TEST_TABLE.getNameAsString(),
              TEST_FAMILY,
              HConstants.EMPTY_BYTE_ARRAY,
              USER_ADMIN_CF.getShortName(),
              Permission.Action.READ));

      // Check for qualifier access user
      assertTrue(
          AccessControlClient.hasPermission(
              conn,
              TEST_TABLE.getNameAsString(),
              TEST_FAMILY,
              TEST_QUALIFIER,
              user2.getShortName(),
              Permission.Action.READ,
              Permission.Action.WRITE));
      assertFalse(
          AccessControlClient.hasPermission(
              conn,
              TEST_TABLE.getNameAsString(),
              TEST_FAMILY,
              TEST_QUALIFIER,
              user2.getShortName(),
              Permission.Action.EXEC,
              Permission.Action.READ));
      assertFalse(
          AccessControlClient.hasPermission(
              conn,
              TEST_TABLE.getNameAsString(),
              HConstants.EMPTY_BYTE_ARRAY,
              TEST_QUALIFIER,
              USER_RW.getShortName(),
              Permission.Action.WRITE,
              Permission.Action.READ));

      // exception scenarios
      try {
        // test case with table name as null
        assertTrue(
            AccessControlClient.hasPermission(
                conn,
                null,
                HConstants.EMPTY_BYTE_ARRAY,
                HConstants.EMPTY_BYTE_ARRAY,
                null,
                Permission.Action.READ));
        fail("this should have thrown IllegalArgumentException");
      } catch (IllegalArgumentException ex) {
        // expected
      }
      try {
        // test case with username as null
        assertTrue(
            AccessControlClient.hasPermission(
                conn,
                TEST_TABLE.getNameAsString(),
                HConstants.EMPTY_BYTE_ARRAY,
                HConstants.EMPTY_BYTE_ARRAY,
                null,
                Permission.Action.READ));
        fail("this should have thrown IllegalArgumentException");
      } catch (IllegalArgumentException ex) {
        // expected
      }

      revokeFromNamespaceUsingAccessControlClient(
          TEST_UTIL,
          conn,
          user1.getShortName(),
          NamespaceDescriptor.DEFAULT_NAMESPACE.getName(),
          Permission.Action.ADMIN,
          Permission.Action.CREATE,
          Permission.Action.READ);
      revokeFromTableUsingAccessControlClient(
          TEST_UTIL,
          conn,
          user2.getShortName(),
          TEST_TABLE,
          TEST_FAMILY,
          TEST_QUALIFIER,
          Permission.Action.READ,
          Permission.Action.WRITE);
    } finally {
      if (conn != null) {
        conn.close();
      }
    }
    cleanUpTables();
    tearDown();
  }
}
