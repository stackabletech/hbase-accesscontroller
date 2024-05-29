package tech.stackable.hbase;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.hbase.*;
import org.apache.hadoop.hbase.client.Admin;
import org.apache.hadoop.hbase.client.Connection;
import org.apache.hadoop.hbase.client.RegionInfo;
import org.apache.hadoop.hbase.client.TableDescriptor;
import org.apache.hadoop.hbase.coprocessor.*;
import org.apache.hadoop.hbase.io.hfile.HFile;
import org.apache.hadoop.hbase.master.MasterCoprocessorHost;
import org.apache.hadoop.hbase.regionserver.HRegion;
import org.apache.hadoop.hbase.regionserver.RegionCoprocessorHost;
import org.apache.hadoop.hbase.regionserver.RegionServerCoprocessorHost;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.access.AccessControlConstants;
import org.apache.hadoop.hbase.security.access.AccessController;
import org.apache.hadoop.hbase.security.access.TestAccessController;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.security.GroupMappingServiceProvider;
import org.apache.hadoop.security.ShellBasedUnixGroupsMapping;
import org.apache.hadoop.security.UserGroupInformation;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestOpenPolicyAgentAccessController {
  protected static final Logger LOG =
      LoggerFactory.getLogger(TestOpenPolicyAgentAccessController.class);
  protected static final HBaseTestingUtility TEST_UTIL = new HBaseTestingUtility();
  protected static HRegion REGION;
  private static Configuration conf;

  private static final String GROUP_ADMIN = "group_admin";
  private static final String GROUP_CREATE = "group_create";
  private static final String GROUP_READ = "group_read";
  private static final String GROUP_WRITE = "group_write";

  private static User USER_GROUP_ADMIN;
  private static User USER_GROUP_CREATE;
  private static User USER_GROUP_READ;
  private static User USER_GROUP_WRITE;

  private static User SUPERUSER;
  // user granted with all global permission
  private static User USER_ADMIN;
  // user with rw permissions on column family.
  private static User USER_RW;
  // user with read-only permissions
  private static User USER_RO;
  // user is table owner. will have all permissions on table
  private static User USER_OWNER;
  // user with create table permissions alone
  private static User USER_CREATE;
  // user with no permissions
  private static User USER_NONE;
  // user with admin rights on the column family
  private static User USER_ADMIN_CF;

  private static TableName TEST_TABLE = TableName.valueOf("testtable1");
  private static TableName TEST_TABLE2 = TableName.valueOf("testtable2");
  private static byte[] TEST_FAMILY = Bytes.toBytes("f1");
  private static byte[] TEST_QUALIFIER = Bytes.toBytes("q1");
  private static byte[] TEST_ROW = Bytes.toBytes("r1");

  private static Connection systemUserConnection;

  private static MasterCoprocessorEnvironment CP_ENV;
  private static RegionServerCoprocessorEnvironment RSCP_ENV;
  private static RegionCoprocessorEnvironment RCP_ENV;

  @Test
  public void testOpenPolicyAgentAccessController() throws Exception {
    LOG.info("testOpenPolicyAgentAccessController - start");

    OpenPolicyAgentAccessController accessController;
    conf = TEST_UTIL.getConfiguration();
    conf.setInt(HConstants.REGION_SERVER_HIGH_PRIORITY_HANDLER_COUNT, 10);

    conf.set(
        CommonConfigurationKeys.HADOOP_SECURITY_GROUP_MAPPING,
        MyShellBasedUnixGroupsMapping.class.getName());

    UserGroupInformation.setConfiguration(conf);

    conf.set(
        CommonConfigurationKeys.HADOOP_SECURITY_GROUP_MAPPING,
        TestAccessController.MyShellBasedUnixGroupsMapping.class.getName());

    conf.set("hadoop.security.authorization", "false");
    conf.set("hadoop.security.authentication", "simple");
    conf.set(
        CoprocessorHost.MASTER_COPROCESSOR_CONF_KEY,
        OpenPolicyAgentAccessController.class.getName() + "," + MasterSyncObserver.class.getName());
    conf.set(
        CoprocessorHost.REGION_COPROCESSOR_CONF_KEY,
        OpenPolicyAgentAccessController.class.getName());
    conf.set(
        CoprocessorHost.REGIONSERVER_COPROCESSOR_CONF_KEY,
        OpenPolicyAgentAccessController.class.getName());

    conf.setInt(HFile.FORMAT_VERSION_KEY, 3);
    conf.set(User.HBASE_SECURITY_AUTHORIZATION_CONF_KEY, "false");
    conf.setBoolean(AccessControlConstants.EXEC_PERMISSION_CHECKS_KEY, true);

    TEST_UTIL.startMiniCluster();
    MasterCoprocessorHost masterCpHost =
        TEST_UTIL.getMiniHBaseCluster().getMaster().getMasterCoprocessorHost();

    masterCpHost.load(OpenPolicyAgentAccessController.class, Coprocessor.PRIORITY_HIGHEST, conf);
    accessController = masterCpHost.findCoprocessor(OpenPolicyAgentAccessController.class);

    CP_ENV =
        masterCpHost.createEnvironment(accessController, Coprocessor.PRIORITY_HIGHEST, 1, conf);
    RegionServerCoprocessorHost rsCpHost =
        TEST_UTIL.getMiniHBaseCluster().getRegionServer(0).getRegionServerCoprocessorHost();
    RSCP_ENV = rsCpHost.createEnvironment(accessController, Coprocessor.PRIORITY_HIGHEST, 1, conf);

    // create a set of test users
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

    HTableDescriptor htd = new HTableDescriptor(TEST_TABLE);
    HColumnDescriptor hcd = new HColumnDescriptor(TEST_FAMILY);
    hcd.setMaxVersions(100);
    htd.addFamily(hcd);
    htd.setOwner(USER_OWNER);
    createTable(TEST_UTIL, TEST_UTIL.getAdmin(), htd, new byte[][] {Bytes.toBytes("s")});

    HRegion region = TEST_UTIL.getHBaseCluster().getRegions(TEST_TABLE).get(0);
    RegionCoprocessorHost rcpHost = region.getCoprocessorHost();
    RCP_ENV = rcpHost.createEnvironment(accessController, Coprocessor.PRIORITY_HIGHEST, 1, conf);

    TEST_UTIL.shutdownMiniCluster();
    LOG.info("testAccessController - complete");
  }

  @Test
  public void testAccessController() throws Exception {
    LOG.info("testAccessController - start");

    AccessController accessController;
    conf = TEST_UTIL.getConfiguration();
    conf.setInt(HConstants.REGION_SERVER_HIGH_PRIORITY_HANDLER_COUNT, 10);

    conf.set(
        CommonConfigurationKeys.HADOOP_SECURITY_GROUP_MAPPING,
        MyShellBasedUnixGroupsMapping.class.getName());

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
    conf.set(User.HBASE_SECURITY_AUTHORIZATION_CONF_KEY, "false");
    conf.setBoolean(AccessControlConstants.EXEC_PERMISSION_CHECKS_KEY, true);

    TEST_UTIL.startMiniCluster();
    MasterCoprocessorHost masterCpHost =
        TEST_UTIL.getMiniHBaseCluster().getMaster().getMasterCoprocessorHost();

    masterCpHost.load(AccessController.class, Coprocessor.PRIORITY_HIGHEST, conf);
    accessController = masterCpHost.findCoprocessor(AccessController.class);

    CP_ENV =
        masterCpHost.createEnvironment(accessController, Coprocessor.PRIORITY_HIGHEST, 1, conf);
    RegionServerCoprocessorHost rsCpHost =
        TEST_UTIL.getMiniHBaseCluster().getRegionServer(0).getRegionServerCoprocessorHost();
    RSCP_ENV = rsCpHost.createEnvironment(accessController, Coprocessor.PRIORITY_HIGHEST, 1, conf);

    // create a set of test users
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

    HTableDescriptor htd = new HTableDescriptor(TEST_TABLE);
    HColumnDescriptor hcd = new HColumnDescriptor(TEST_FAMILY);
    hcd.setMaxVersions(100);
    htd.addFamily(hcd);
    htd.setOwner(USER_OWNER);
    createTable(TEST_UTIL, TEST_UTIL.getAdmin(), htd, new byte[][] {Bytes.toBytes("s")});

    HRegion region = TEST_UTIL.getHBaseCluster().getRegions(TEST_TABLE).get(0);
    RegionCoprocessorHost rcpHost = region.getCoprocessorHost();
    RCP_ENV = rcpHost.createEnvironment(accessController, Coprocessor.PRIORITY_HIGHEST, 1, conf);

    TEST_UTIL.shutdownMiniCluster();
    LOG.info("testAccessController - complete");
  }

  public static void createTable(
      HBaseTestingUtility testUtil, Admin admin, TableDescriptor htd, byte[][] splitKeys)
      throws Exception {
    // NOTE: We need a latch because admin is not sync,
    // so the postOp coprocessor method may be called after the admin operation returned.
    MasterSyncObserver observer =
        testUtil
            .getHBaseCluster()
            .getMaster()
            .getMasterCoprocessorHost()
            .findCoprocessor(MasterSyncObserver.class);
    observer.tableCreationLatch = new CountDownLatch(1);
    if (splitKeys != null) {
      admin.createTable(htd, splitKeys);
    } else {
      admin.createTable(htd);
    }
    observer.tableCreationLatch.await();
    observer.tableCreationLatch = null;
    testUtil.waitUntilAllRegionsAssigned(htd.getTableName());
  }

  /*
   * Dummy ShellBasedUnixGroupsMapping class to retrieve the groups for the test users.
   */
  public static class MyShellBasedUnixGroupsMapping extends ShellBasedUnixGroupsMapping
      implements GroupMappingServiceProvider {
    @Override
    public List<String> getGroups(String user) throws IOException {
      if (user.equals("globalGroupUser1")) {
        return Arrays.asList(new String[] {"group_admin"});
      } else if (user.equals("globalGroupUser2")) {
        return Arrays.asList(new String[] {"group_admin", "group_create"});
      } else if (user.equals("nsGroupUser1")) {
        return Arrays.asList(new String[] {"ns_group1"});
      } else if (user.equals("nsGroupUser2")) {
        return Arrays.asList(new String[] {"ns_group2"});
      } else if (user.equals("tableGroupUser1")) {
        return Arrays.asList(new String[] {"table_group1"});
      } else if (user.equals("tableGroupUser2")) {
        return Arrays.asList(new String[] {"table_group2"});
      } else {
        return super.getGroups(user);
      }
    }
  }

  public static class MasterSyncObserver implements MasterCoprocessor, MasterObserver {
    volatile CountDownLatch tableCreationLatch = null;
    volatile CountDownLatch tableDeletionLatch = null;

    @Override
    public Optional<MasterObserver> getMasterObserver() {
      return Optional.of(this);
    }

    @Override
    public void postCompletedCreateTableAction(
        final ObserverContext<MasterCoprocessorEnvironment> ctx,
        TableDescriptor desc,
        RegionInfo[] regions)
        throws IOException {
      // the AccessController test, some times calls only and directly the
      // postCompletedCreateTableAction()
      if (tableCreationLatch != null) {
        tableCreationLatch.countDown();
      }
    }

    @Override
    public void postCompletedDeleteTableAction(
        final ObserverContext<MasterCoprocessorEnvironment> ctx, final TableName tableName)
        throws IOException {
      // the AccessController test, some times calls only and directly the
      // postCompletedDeleteTableAction()
      if (tableDeletionLatch != null) {
        tableDeletionLatch.countDown();
      }
    }
  }
}
