package tech.stackable.hbase;

import static org.apache.hadoop.hbase.AuthUtil.toGroupEntry;
import static org.apache.hadoop.hbase.security.access.SecureTestUtil.*;
import static org.junit.Assert.*;

import com.google.protobuf.BlockingRpcChannel;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.hbase.*;
import org.apache.hadoop.hbase.client.*;
import org.apache.hadoop.hbase.coprocessor.*;
import org.apache.hadoop.hbase.io.hfile.HFile;
import org.apache.hadoop.hbase.master.MasterCoprocessorHost;
import org.apache.hadoop.hbase.protobuf.generated.AccessControlProtos;
import org.apache.hadoop.hbase.regionserver.HRegion;
import org.apache.hadoop.hbase.regionserver.RegionCoprocessorHost;
import org.apache.hadoop.hbase.security.Superusers;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.access.*;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.security.UserGroupInformation;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestOpenPolicyAgentAccessController {
  protected static final Logger LOG =
      LoggerFactory.getLogger(TestOpenPolicyAgentAccessController.class);
  protected static final HBaseTestingUtility TEST_UTIL = new HBaseTestingUtility();
  private static Configuration conf;
  private static Connection systemUserConnection;
  private static AccessController ACCESS_CONTROLLER;

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

  // @Test
  //  public void testOpenPolicyAgentAccessController() throws Exception {
  //    LOG.info("testOpenPolicyAgentAccessController - start");
  //
  //    conf = TEST_UTIL.getConfiguration();
  //    conf.setInt(HConstants.REGION_SERVER_HIGH_PRIORITY_HANDLER_COUNT, 10);
  //
  //    conf.set(
  //        CommonConfigurationKeys.HADOOP_SECURITY_GROUP_MAPPING,
  //        TestAccessController.MyShellBasedUnixGroupsMapping.class.getName());
  //
  //    UserGroupInformation.setConfiguration(conf);
  //
  //    conf.set(
  //        CommonConfigurationKeys.HADOOP_SECURITY_GROUP_MAPPING,
  //        TestAccessController.MyShellBasedUnixGroupsMapping.class.getName());
  //
  //    conf.set("hadoop.security.authorization", "false");
  //    conf.set("hadoop.security.authentication", "simple");
  //    conf.set(
  //        CoprocessorHost.MASTER_COPROCESSOR_CONF_KEY,
  //        OpenPolicyAgentAccessController.class.getName() + "," +
  // MasterSyncObserver.class.getName());
  //    conf.set(
  //        CoprocessorHost.REGION_COPROCESSOR_CONF_KEY,
  //        OpenPolicyAgentAccessController.class.getName());
  //    conf.set(
  //        CoprocessorHost.REGIONSERVER_COPROCESSOR_CONF_KEY,
  //        OpenPolicyAgentAccessController.class.getName());
  //
  //    conf.setInt(HFile.FORMAT_VERSION_KEY, 3);
  //    conf.set(User.HBASE_SECURITY_AUTHORIZATION_CONF_KEY, "false");
  //    conf.setBoolean(AccessControlConstants.EXEC_PERMISSION_CHECKS_KEY, true);
  //
  //    TEST_UTIL.startMiniCluster();
  //    MasterCoprocessorHost masterCpHost =
  //        TEST_UTIL.getMiniHBaseCluster().getMaster().getMasterCoprocessorHost();
  //
  //    masterCpHost.load(OpenPolicyAgentAccessController.class, Coprocessor.PRIORITY_HIGHEST,
  // conf);
  //
  //    USER_OWNER = User.createUserForTesting(conf, "owner", new String[0]);
  //
  //    HTableDescriptor htd = new HTableDescriptor(TEST_TABLE);
  //    HColumnDescriptor hcd = new HColumnDescriptor(TEST_FAMILY);
  //    hcd.setMaxVersions(100);
  //    htd.addFamily(hcd);
  //    htd.setOwner(USER_OWNER);
  //    createTable(TEST_UTIL, TEST_UTIL.getAdmin(), htd, new byte[][] {Bytes.toBytes("s")});
  //
  //    TEST_UTIL.shutdownMiniCluster();
  //    LOG.info("testOpenPolicyAgentAccessController - complete");
  //  }

  @BeforeClass
  public static void setupBeforeClass() throws Exception {
    conf = TEST_UTIL.getConfiguration();
    conf.setInt(HConstants.REGION_SERVER_HIGH_PRIORITY_HANDLER_COUNT, 10);

    conf.set(
        CommonConfigurationKeys.HADOOP_SECURITY_GROUP_MAPPING,
        TestAccessController.MyShellBasedUnixGroupsMapping.class.getName());

    UserGroupInformation.setConfiguration(conf);

    conf.set(
        CommonConfigurationKeys.HADOOP_SECURITY_GROUP_MAPPING,
        TestAccessController.MyShellBasedUnixGroupsMapping.class.getName());

    conf.set("hadoop.security.authorization", "false");
    conf.set("hadoop.security.authentication", "simple");
    conf.set(
        CoprocessorHost.MASTER_COPROCESSOR_CONF_KEY,
        AccessController.class.getName() + "," + MasterSyncObserver.class.getName());
    conf.set(CoprocessorHost.REGION_COPROCESSOR_CONF_KEY, AccessController.class.getName());
    conf.set(CoprocessorHost.REGIONSERVER_COPROCESSOR_CONF_KEY, AccessController.class.getName());

    conf.setInt(HFile.FORMAT_VERSION_KEY, 3);
    conf.set(User.HBASE_SECURITY_AUTHORIZATION_CONF_KEY, "true");
    conf.setBoolean(AccessControlConstants.EXEC_PERMISSION_CHECKS_KEY, true);
    configureSuperuser(conf);

    TEST_UTIL.startMiniCluster();
    MasterCoprocessorHost masterCpHost =
        TEST_UTIL.getMiniHBaseCluster().getMaster().getMasterCoprocessorHost();
    masterCpHost.load(AccessController.class, Coprocessor.PRIORITY_HIGHEST, conf);
    ACCESS_CONTROLLER = masterCpHost.findCoprocessor(AccessController.class);

    TEST_UTIL.waitUntilAllRegionsAssigned(PermissionStorage.ACL_TABLE_NAME);

    SUPERUSER = User.createUserForTesting(conf, "admin", new String[] {"supergroup"});
    USER_ADMIN = User.createUserForTesting(conf, "admin2", new String[0]);
    USER_RW = User.createUserForTesting(conf, "rwuser", new String[0]);
    USER_RO = User.createUserForTesting(conf, "rouser", new String[0]);
    USER_OWNER = User.createUserForTesting(conf, "owner", new String[0]);
    USER_CREATE = User.createUserForTesting(conf, "tbl_create", new String[0]);
    USER_NONE = User.createUserForTesting(conf, "nouser", new String[0]);
    USER_ADMIN_CF = User.createUserForTesting(conf, "col_family_admin", new String[0]);

    USER_GROUP_ADMIN =
        User.createUserForTesting(conf, "user_group_admin", new String[] {GROUP_ADMIN});
    USER_GROUP_CREATE =
        User.createUserForTesting(conf, "user_group_create", new String[] {GROUP_CREATE});
    USER_GROUP_READ = User.createUserForTesting(conf, "user_group_read", new String[] {GROUP_READ});
    USER_GROUP_WRITE =
        User.createUserForTesting(conf, "user_group_write", new String[] {GROUP_WRITE});

    systemUserConnection = TEST_UTIL.getConnection();
    setUpTableAndUserPermissions();
  }

  private static void setUpTableAndUserPermissions() throws Exception {
    HTableDescriptor htd = new HTableDescriptor(TEST_TABLE);
    HColumnDescriptor hcd = new HColumnDescriptor(TEST_FAMILY);
    hcd.setMaxVersions(100);
    htd.addFamily(hcd);
    htd.setOwner(USER_OWNER);
    createTable(TEST_UTIL, TEST_UTIL.getAdmin(), htd, new byte[][] {Bytes.toBytes("s")});

    HRegion region = TEST_UTIL.getHBaseCluster().getRegions(TEST_TABLE).get(0);
    RegionCoprocessorHost rcpHost = region.getCoprocessorHost();
    rcpHost.createEnvironment(ACCESS_CONTROLLER, Coprocessor.PRIORITY_HIGHEST, 1, conf);

    // Set up initial grants

    grantGlobal(
        TEST_UTIL,
        USER_ADMIN.getShortName(),
        Permission.Action.ADMIN,
        Permission.Action.CREATE,
        Permission.Action.READ,
        Permission.Action.WRITE);

    grantOnTable(
        TEST_UTIL,
        USER_RW.getShortName(),
        TEST_TABLE,
        TEST_FAMILY,
        null,
        Permission.Action.READ,
        Permission.Action.WRITE);

    // USER_CREATE is USER_RW plus CREATE permissions
    grantOnTable(
        TEST_UTIL,
        USER_CREATE.getShortName(),
        TEST_TABLE,
        null,
        null,
        Permission.Action.CREATE,
        Permission.Action.READ,
        Permission.Action.WRITE);

    grantOnTable(
        TEST_UTIL, USER_RO.getShortName(), TEST_TABLE, TEST_FAMILY, null, Permission.Action.READ);

    grantOnTable(
        TEST_UTIL,
        USER_ADMIN_CF.getShortName(),
        TEST_TABLE,
        TEST_FAMILY,
        null,
        Permission.Action.ADMIN,
        Permission.Action.CREATE);

    grantGlobal(TEST_UTIL, toGroupEntry(GROUP_ADMIN), Permission.Action.ADMIN);
    grantGlobal(TEST_UTIL, toGroupEntry(GROUP_CREATE), Permission.Action.CREATE);
    grantGlobal(TEST_UTIL, toGroupEntry(GROUP_READ), Permission.Action.READ);
    grantGlobal(TEST_UTIL, toGroupEntry(GROUP_WRITE), Permission.Action.WRITE);

    assertEquals(5, PermissionStorage.getTablePermissions(conf, TEST_TABLE).size());
    int size = 0;
    try {
      size =
          AccessControlClient.getUserPermissions(systemUserConnection, TEST_TABLE.toString())
              .size();
    } catch (Throwable e) {
      LOG.error("error during call of AccessControlClient.getUserPermissions. ", e);
      fail("error during call of AccessControlClient.getUserPermissions.");
    }
    assertEquals(5, size);
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {
    cleanUp();
    TEST_UTIL.shutdownMiniCluster();
  }

  private static void cleanUp() throws Exception {
    // Clean the _acl_ table
    try {
      deleteTable(TEST_UTIL, TEST_TABLE);
    } catch (TableNotFoundException ex) {
      // Test deleted the table, no problem
      LOG.info("Test deleted table " + TEST_TABLE);
    }
    // Verify all table/namespace permissions are erased
    assertEquals(0, PermissionStorage.getTablePermissions(conf, TEST_TABLE).size());
    assertEquals(
        0,
        PermissionStorage.getNamespacePermissions(conf, TEST_TABLE.getNamespaceAsString()).size());
  }

  @Test
  public void testGetUserPermissions() throws Throwable {
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
  }

  @Test
  public void testHasPermission() throws Throwable {
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
  }

  private void validateTableACLForGetUserPermissions(
      final Connection conn,
      User nSUser1,
      User tableGroupUser1,
      User tableGroupUser2,
      String nsPrefix,
      TableName table1,
      TableName table2,
      byte[] TEST_QUALIFIER2,
      Collection<String> superUsers)
      throws Throwable {
    AccessTestAction tableUserPermissionAction =
        new AccessTestAction() {
          @Override
          public Object run() throws Exception {
            try (Connection conn = ConnectionFactory.createConnection(conf)) {
              conn.getAdmin()
                  .getUserPermissions(
                      GetUserPermissionsRequest.newBuilder(TEST_TABLE)
                          .withFamily(TEST_FAMILY)
                          .withQualifier(TEST_QUALIFIER)
                          .withUserName("dummy")
                          .build());
            }
            return null;
          }
        };
    verifyAllowed(tableUserPermissionAction, SUPERUSER, USER_ADMIN, USER_OWNER, USER_ADMIN_CF);
    verifyDenied(tableUserPermissionAction, USER_CREATE, USER_RW, USER_RO, USER_NONE, USER_CREATE);

    List<UserPermission> userPermissions;
    assertEquals(12, AccessControlClient.getUserPermissions(conn, nsPrefix + ".*").size());
    assertEquals(6, AccessControlClient.getUserPermissions(conn, table1.getNameAsString()).size());
    assertEquals(
        6,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), HConstants.EMPTY_STRING)
            .size());
    userPermissions =
        AccessControlClient.getUserPermissions(
            conn, table1.getNameAsString(), USER_ADMIN_CF.getName());
    verifyGetUserPermissionResult(userPermissions, 1, null, null, USER_ADMIN_CF.getName(), null);
    assertEquals(
        0,
        AccessControlClient.getUserPermissions(conn, table1.getNameAsString(), nSUser1.getName())
            .size());
    // Table group user ACL
    assertEquals(
        1,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), tableGroupUser1.getName())
            .size());
    assertEquals(
        1,
        AccessControlClient.getUserPermissions(
                conn, table2.getNameAsString(), tableGroupUser2.getName())
            .size());

    // Table Users + CF
    assertEquals(
        12,
        AccessControlClient.getUserPermissions(conn, nsPrefix + ".*", HConstants.EMPTY_BYTE_ARRAY)
            .size());
    userPermissions = AccessControlClient.getUserPermissions(conn, nsPrefix + ".*", TEST_FAMILY);
    verifyGetUserPermissionResult(userPermissions, 3, TEST_FAMILY, null, null, null);
    assertEquals(
        0,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), Bytes.toBytes("dummmyCF"))
            .size());

    // Table Users + CF + User
    assertEquals(
        3,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), TEST_FAMILY, HConstants.EMPTY_STRING)
            .size());
    userPermissions =
        AccessControlClient.getUserPermissions(
            conn, table1.getNameAsString(), TEST_FAMILY, USER_ADMIN_CF.getName());
    verifyGetUserPermissionResult(
        userPermissions, 1, null, null, USER_ADMIN_CF.getName(), superUsers);
    assertEquals(
        0,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), TEST_FAMILY, nSUser1.getName())
            .size());

    // Table Users + CF + CQ
    assertEquals(
        3,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), TEST_FAMILY, HConstants.EMPTY_BYTE_ARRAY)
            .size());
    assertEquals(
        1,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), TEST_FAMILY, TEST_QUALIFIER)
            .size());
    assertEquals(
        1,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), TEST_FAMILY, TEST_QUALIFIER2)
            .size());
    assertEquals(
        2,
        AccessControlClient.getUserPermissions(
                conn,
                table1.getNameAsString(),
                HConstants.EMPTY_BYTE_ARRAY,
                HConstants.EMPTY_BYTE_ARRAY,
                USER_RW.getName())
            .size());
    assertEquals(
        0,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), TEST_FAMILY, Bytes.toBytes("dummmyCQ"))
            .size());

    // Table Users + CF + CQ + User
    assertEquals(
        3,
        AccessControlClient.getUserPermissions(
                conn,
                table1.getNameAsString(),
                TEST_FAMILY,
                HConstants.EMPTY_BYTE_ARRAY,
                HConstants.EMPTY_STRING)
            .size());
    assertEquals(
        1,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), TEST_FAMILY, TEST_QUALIFIER, USER_RW.getName())
            .size());
    assertEquals(
        1,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), TEST_FAMILY, TEST_QUALIFIER2, USER_RW.getName())
            .size());
    assertEquals(
        0,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), TEST_FAMILY, TEST_QUALIFIER2, nSUser1.getName())
            .size());
  }

  private void validateNamespaceUserACLForGetUserPermissions(
      final Connection conn,
      User nSUser1,
      User nSUser3,
      User nsGroupUser1,
      User nsGroupUser2,
      String nsPrefix,
      final String namespace1,
      String namespace2)
      throws Throwable {
    AccessTestAction namespaceUserPermissionAction =
        new AccessTestAction() {
          @Override
          public Object run() throws Exception {
            try (Connection conn = ConnectionFactory.createConnection(conf)) {
              conn.getAdmin()
                  .getUserPermissions(
                      GetUserPermissionsRequest.newBuilder(namespace1)
                          .withUserName("dummy")
                          .build());
            }
            return null;
          }
        };
    verifyAllowed(
        namespaceUserPermissionAction,
        SUPERUSER,
        USER_GROUP_ADMIN,
        USER_ADMIN,
        nSUser1,
        nsGroupUser1);
    verifyDenied(
        namespaceUserPermissionAction,
        USER_GROUP_CREATE,
        USER_GROUP_READ,
        USER_GROUP_WRITE,
        nSUser3,
        nsGroupUser2);

    List<UserPermission> userPermissions;
    assertEquals(6, AccessControlClient.getUserPermissions(conn, "@" + nsPrefix + ".*").size());
    assertEquals(3, AccessControlClient.getUserPermissions(conn, "@" + namespace1).size());
    assertEquals(
        3,
        AccessControlClient.getUserPermissions(conn, "@" + namespace1, HConstants.EMPTY_STRING)
            .size());
    userPermissions =
        AccessControlClient.getUserPermissions(conn, "@" + namespace1, nSUser1.getName());
    verifyGetUserPermissionResult(userPermissions, 1, null, null, nSUser1.getName(), null);
    userPermissions =
        AccessControlClient.getUserPermissions(conn, "@" + namespace1, nSUser3.getName());
    verifyGetUserPermissionResult(userPermissions, 1, null, null, nSUser3.getName(), null);
    assertEquals(
        0,
        AccessControlClient.getUserPermissions(conn, "@" + namespace1, USER_ADMIN.getName())
            .size());
    // Namespace group user ACL
    assertEquals(
        1,
        AccessControlClient.getUserPermissions(conn, "@" + namespace1, nsGroupUser1.getName())
            .size());
    assertEquals(
        1,
        AccessControlClient.getUserPermissions(conn, "@" + namespace2, nsGroupUser2.getName())
            .size());
  }

  private void validateGlobalUserACLForGetUserPermissions(
      final Connection conn,
      User nSUser1,
      User globalGroupUser1,
      User globalGroupUser2,
      Collection<String> superUsers,
      int superUserCount)
      throws Throwable {
    // Verify action privilege
    AccessTestAction globalUserPermissionAction =
        new AccessTestAction() {
          @Override
          public Object run() throws Exception {
            try (Connection conn = ConnectionFactory.createConnection(conf)) {
              conn.getAdmin()
                  .getUserPermissions(
                      GetUserPermissionsRequest.newBuilder().withUserName("dummy").build());
            }
            return null;
          }
        };
    verifyAllowed(globalUserPermissionAction, SUPERUSER, USER_ADMIN, USER_GROUP_ADMIN);
    verifyDenied(globalUserPermissionAction, USER_GROUP_CREATE, USER_GROUP_READ, USER_GROUP_WRITE);

    // Validate global user permission
    List<UserPermission> userPermissions;
    assertEquals(5 + superUserCount, AccessControlClient.getUserPermissions(conn, null).size());
    assertEquals(
        5 + superUserCount,
        AccessControlClient.getUserPermissions(conn, HConstants.EMPTY_STRING).size());
    assertEquals(
        5 + superUserCount,
        AccessControlClient.getUserPermissions(conn, null, HConstants.EMPTY_STRING).size());
    userPermissions = AccessControlClient.getUserPermissions(conn, null, USER_ADMIN.getName());
    verifyGetUserPermissionResult(userPermissions, 1, null, null, USER_ADMIN.getName(), superUsers);
    assertEquals(0, AccessControlClient.getUserPermissions(conn, null, nSUser1.getName()).size());
    // Global group user ACL
    assertEquals(
        1, AccessControlClient.getUserPermissions(conn, null, globalGroupUser1.getName()).size());
    assertEquals(
        2, AccessControlClient.getUserPermissions(conn, null, globalGroupUser2.getName()).size());
  }

  private void verifyGetUserPermissionResult(
      List<UserPermission> userPermissions,
      int resultCount,
      byte[] cf,
      byte[] cq,
      String userName,
      Collection<String> superUsers) {
    assertEquals(resultCount, userPermissions.size());

    for (UserPermission perm : userPermissions) {
      if (perm.getPermission() instanceof TablePermission) {
        TablePermission tablePerm = (TablePermission) perm.getPermission();
        if (cf != null) {
          assertTrue(Bytes.equals(cf, tablePerm.getFamily()));
        }
        if (cq != null) {
          assertTrue(Bytes.equals(cq, tablePerm.getQualifier()));
        }
        if (userName != null && (superUsers == null || !superUsers.contains(perm.getUser()))) {
          assertTrue(userName.equals(perm.getUser()));
        }
      } else if (perm.getPermission() instanceof NamespacePermission
          || perm.getPermission() instanceof GlobalPermission) {
        if (userName != null && (superUsers == null || !superUsers.contains(perm.getUser()))) {
          assertTrue(userName.equals(perm.getUser()));
        }
      }
    }
  }

  private void createTestTable(TableName tname, byte[] cf) throws Exception {
    HTableDescriptor htd = new HTableDescriptor(tname);
    HColumnDescriptor hcd = new HColumnDescriptor(cf);
    hcd.setMaxVersions(100);
    htd.addFamily(hcd);
    htd.setOwner(USER_OWNER);
    createTable(TEST_UTIL, TEST_UTIL.getAdmin(), htd, new byte[][] {Bytes.toBytes("s")});
  }
}
