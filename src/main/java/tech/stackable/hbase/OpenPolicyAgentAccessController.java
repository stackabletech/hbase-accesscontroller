package tech.stackable.hbase;

import java.io.IOException;
import java.util.*;
import org.apache.hadoop.hbase.*;
import org.apache.hadoop.hbase.client.*;
import org.apache.hadoop.hbase.coprocessor.*;
import org.apache.hadoop.hbase.io.hfile.HFile;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.UserProvider;
import org.apache.hadoop.hbase.security.access.*;
import org.apache.hadoop.hbase.wal.WALEdit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OpenPolicyAgentAccessController extends AccessController {
  private static final Logger LOG = LoggerFactory.getLogger(OpenPolicyAgentAccessController.class);

  private UserProvider userProvider;
  private boolean authorizationEnabled;
  private boolean cellFeaturesEnabled;

  @Override
  public void start(CoprocessorEnvironment env) throws IOException {
    super.start(env);

    authorizationEnabled = AccessChecker.isAuthorizationSupported(env.getConfiguration());
    if (!authorizationEnabled) {
      LOG.warn(
          "OpenPolicyAgentAccessController has been loaded with authorization checks DISABLED!");
    }

    cellFeaturesEnabled =
        (HFile.getFormatVersion(env.getConfiguration()) >= HFile.MIN_FORMAT_VERSION_WITH_TAGS);
    if (!cellFeaturesEnabled) {
      LOG.info(
          "A minimum HFile version of "
              + HFile.MIN_FORMAT_VERSION_WITH_TAGS
              + " is required to persist cell ACLs. Consider setting "
              + HFile.FORMAT_VERSION_KEY
              + " accordingly.");
    }
    // set the user-provider.
    this.userProvider = UserProvider.instantiate(env.getConfiguration());
  }

  // TODO replace with user that returns the whole name for getShortName()
  private User getActiveUser(ObserverContext<?> ctx) throws IOException {
    // for non-rpc handling, fallback to system user
    Optional<User> optionalUser = ctx.getCaller();
    if (optionalUser.isPresent()) {
      return optionalUser.get();
    }
    return userProvider.getCurrent();
  }

  @Override
  public void postCompletedCreateTableAction(
      final ObserverContext<MasterCoprocessorEnvironment> c,
      final TableDescriptor desc,
      final RegionInfo[] regions) {
    LOG.info("postCompletedCreateTableAction: start");
  }

  @Override
  public void prePut(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final Put put,
      final WALEdit edit,
      final Durability durability)
      throws IOException {
    User user = getActiveUser(c);
    LOG.info("prePut: start with [{}]", user);
  }

  @Override
  public void preDelete(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final Delete delete,
      final WALEdit edit,
      final Durability durability)
      throws IOException {
    User user = getActiveUser(c);
    LOG.info("preDelete: start with [{}]", user);
  }

  @Override
  public Result preAppend(ObserverContext<RegionCoprocessorEnvironment> c, Append append)
      throws IOException {
    User user = getActiveUser(c);
    LOG.info("preAppend: start with [{}]", user);
    return null;
  }
}
