package tech.stackable.hbase;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.hbase.Coprocessor;
import org.apache.hadoop.hbase.HBaseTestingUtility;
import org.apache.hadoop.hbase.HConstants;
import org.apache.hadoop.hbase.coprocessor.CoprocessorHost;
import org.apache.hadoop.hbase.io.hfile.HFile;
import org.apache.hadoop.hbase.master.MasterCoprocessorHost;
import org.apache.hadoop.hbase.regionserver.HRegion;
import org.apache.hadoop.hbase.security.access.TestAccessController;
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
  private static OpenPolicyAgentAccessController ACCESS_CONTROLLER;

  @Test
  public void testSimpleOpaAccess() throws Exception {
    LOG.info("testSimpleOpaAccess - start");

    conf = TEST_UTIL.getConfiguration();
    conf.setInt(HConstants.REGION_SERVER_HIGH_PRIORITY_HANDLER_COUNT, 10);

    UserGroupInformation.setConfiguration(conf);

    conf.set(
        CommonConfigurationKeys.HADOOP_SECURITY_GROUP_MAPPING,
        TestAccessController.MyShellBasedUnixGroupsMapping.class.getName());

    conf.set("hadoop.security.authorization", "false");
    conf.set("hadoop.security.authentication", "simple");
    conf.set(
        CoprocessorHost.MASTER_COPROCESSOR_CONF_KEY,
        OpenPolicyAgentAccessController.class.getName());
    conf.set(
        CoprocessorHost.REGION_COPROCESSOR_CONF_KEY,
        OpenPolicyAgentAccessController.class.getName());
    conf.set(
        CoprocessorHost.REGIONSERVER_COPROCESSOR_CONF_KEY,
        OpenPolicyAgentAccessController.class.getName());

    conf.setInt(HFile.FORMAT_VERSION_KEY, 3);
    // conf.set(User.HBASE_SECURITY_AUTHORIZATION_CONF_KEY, "true");
    // conf.setBoolean(AccessControlConstants.EXEC_PERMISSION_CHECKS_KEY, true);

    TEST_UTIL.startMiniCluster();
    MasterCoprocessorHost masterCpHost =
        TEST_UTIL.getMiniHBaseCluster().getMaster().getMasterCoprocessorHost();

    masterCpHost.load(OpenPolicyAgentAccessController.class, Coprocessor.PRIORITY_HIGHEST, conf);
    ACCESS_CONTROLLER = masterCpHost.findCoprocessor(OpenPolicyAgentAccessController.class);

    LOG.info("testSimpleOpaAccess - complete");
  }
}
