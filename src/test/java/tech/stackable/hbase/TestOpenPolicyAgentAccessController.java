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
import org.apache.hadoop.hbase.client.RegionInfo;
import org.apache.hadoop.hbase.client.TableDescriptor;
import org.apache.hadoop.hbase.coprocessor.*;
import org.apache.hadoop.hbase.io.hfile.HFile;
import org.apache.hadoop.hbase.master.MasterCoprocessorHost;
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
  private static Configuration conf;
  private static User USER_OWNER;

  private static TableName TEST_TABLE = TableName.valueOf("testtable1");
  private static byte[] TEST_FAMILY = Bytes.toBytes("f1");

  @Test
  public void testOpenPolicyAgentAccessController() throws Exception {
    LOG.info("testOpenPolicyAgentAccessController - start");

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

    USER_OWNER = User.createUserForTesting(conf, "owner", new String[0]);

    HTableDescriptor htd = new HTableDescriptor(TEST_TABLE);
    HColumnDescriptor hcd = new HColumnDescriptor(TEST_FAMILY);
    hcd.setMaxVersions(100);
    htd.addFamily(hcd);
    htd.setOwner(USER_OWNER);
    createTable(TEST_UTIL, TEST_UTIL.getAdmin(), htd, new byte[][] {Bytes.toBytes("s")});

    TEST_UTIL.shutdownMiniCluster();
    LOG.info("testOpenPolicyAgentAccessController - complete");
  }

  @Test
  public void testAccessController() throws Exception {
    LOG.info("testAccessController - start");

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

    USER_OWNER = User.createUserForTesting(conf, "owner", new String[0]);

    HTableDescriptor htd = new HTableDescriptor(TEST_TABLE);
    HColumnDescriptor hcd = new HColumnDescriptor(TEST_FAMILY);
    hcd.setMaxVersions(100);
    htd.addFamily(hcd);
    htd.setOwner(USER_OWNER);
    createTable(TEST_UTIL, TEST_UTIL.getAdmin(), htd, new byte[][] {Bytes.toBytes("s")});

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
