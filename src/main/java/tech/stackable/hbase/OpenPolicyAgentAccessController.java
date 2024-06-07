package tech.stackable.hbase;

import com.google.protobuf.RpcCallback;
import com.google.protobuf.RpcController;
import java.io.IOException;
import java.util.Optional;
import org.apache.hadoop.hbase.CoprocessorEnvironment;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.*;
import org.apache.hadoop.hbase.coprocessor.*;
import org.apache.hadoop.hbase.protobuf.generated.AccessControlProtos;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.UserProvider;
import org.apache.hadoop.hbase.security.access.AccessChecker;
import org.apache.hadoop.hbase.security.access.Permission.Action;
import org.apache.hadoop.hbase.wal.WALEdit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tech.stackable.hbase.opa.OpaAclChecker;

public class OpenPolicyAgentAccessController
    implements MasterCoprocessor,
        RegionCoprocessor,
        RegionServerCoprocessor,
        AccessControlProtos.AccessControlService.Interface,
        MasterObserver,
        RegionObserver,
        RegionServerObserver,
        EndpointObserver,
        BulkLoadObserver {
  private static final Logger LOG = LoggerFactory.getLogger(OpenPolicyAgentAccessController.class);

  private UserProvider userProvider;
  private OpaAclChecker opaAclChecker;

  // Opa-related
  public static final String OPA_POLICY_URL_PROP = "hbase.security.authorization.opa.policy.url";
  public static final String OPA_POLICY_DRYRUN = "hbase.security.authorization.opa.policy.dryrun";
  public static final String OPA_POLICY_CACHE =
      "hbase.security.authorization.opa.policy.cache.active";
  public static final String OPA_POLICY_CACHE_TTL_SECONDS =
      "hbase.security.authorization.opa.policy.cache.seconds";
  public static final String OPA_POLICY_CACHE_TTL_SIZE =
      "hbase.security.authorization.opa.policy.cache.size";

  @Override
  public void start(CoprocessorEnvironment env) {
    boolean authorizationEnabled = AccessChecker.isAuthorizationSupported(env.getConfiguration());
    boolean dryRun = env.getConfiguration().getBoolean(OPA_POLICY_DRYRUN, false);
    boolean useCache = env.getConfiguration().getBoolean(OPA_POLICY_CACHE, false);
    int cacheTtlSeconds = env.getConfiguration().getInt(OPA_POLICY_CACHE_TTL_SECONDS, 60);
    long cacheTtlSize = env.getConfiguration().getLong(OPA_POLICY_CACHE_TTL_SIZE, 1000);

    if (!authorizationEnabled) {
      LOG.warn(
          "OpenPolicyAgentAccessController has been loaded with authorization checks DISABLED!");
    }
    if (dryRun) {
      LOG.warn("OpenPolicyAgentAccessController has been loaded in dryRun mode...");
    }

    // set the user-provider.
    this.userProvider = UserProvider.instantiate(env.getConfiguration());

    // opa-related
    this.opaAclChecker =
        new OpaAclChecker(
            authorizationEnabled,
            env.getConfiguration().get(OPA_POLICY_URL_PROP),
            dryRun,
            new OpaAclChecker.CacheConfig(useCache, cacheTtlSeconds, cacheTtlSize));
  }

  public Optional<Long> getAclCacheSize() {
    return opaAclChecker.getAclCacheSize();
  }

  private User getActiveUser(ObserverContext<?> ctx) throws IOException {
    // for non-rpc handling, fallback to system user
    Optional<User> optionalUser = ctx.getCaller();
    if (optionalUser.isPresent()) {
      return optionalUser.get();
    }
    return userProvider.getCurrent();
  }

  @Override
  public void preCreateTable(
      ObserverContext<MasterCoprocessorEnvironment> c, TableDescriptor desc, RegionInfo[] regions)
      throws IOException {
    User user = getActiveUser(c);
    LOG.info("preCreateTable: user [{}]", user);

    opaAclChecker.checkPermissionInfo(user, desc.getTableName(), Action.CREATE);
  }

  @Override
  public void postCompletedCreateTableAction(
      final ObserverContext<MasterCoprocessorEnvironment> c,
      final TableDescriptor desc,
      final RegionInfo[] regions) {
    /*
    The default AccessController uses this method to check on the existence of the ACL table
    and to switch from the current user to the real hbase master user for doing the RPC on the ACL table.
    i.e. we do not need this if we are managing permissions in Opa.
     */
    LOG.info("postCompletedCreateTableAction: not implemented!");
  }

  @Override
  public void preDeleteTable(ObserverContext<MasterCoprocessorEnvironment> c, TableName tableName)
      throws IOException {
    User user = getActiveUser(c);
    LOG.info("preDeleteTable: user [{}]", user);

    // the default access controller treats create/delete as requiring the same permissions.
    opaAclChecker.checkPermissionInfo(user, tableName, Action.CREATE);
  }

  @Override
  public void postDeleteTable(
      ObserverContext<MasterCoprocessorEnvironment> c, final TableName tableName) {
    /*
    The default AccessController switches from the current user to the real hbase login user
    (User.runAsLoginUser) for updating table permissions.
    i.e. we do not need this if we are managing permissions in Opa.
     */
    LOG.info("postDeleteTable: not implemented!");
  }

  @Override
  public void prePut(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final Put put,
      final WALEdit edit,
      final Durability durability)
      throws IOException {
    User user = getActiveUser(c);
    LOG.info("prePut: user [{}]", user);

    opaAclChecker.checkPermissionInfo(
        user, c.getEnvironment().getRegion().getRegionInfo().getTable(), Action.WRITE);
  }

  @Override
  public void preDelete(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final Delete delete,
      final WALEdit edit,
      final Durability durability)
      throws IOException {
    User user = getActiveUser(c);
    LOG.info("preDelete: user [{}]", user);

    // the default access controller uses a second enum - OpType - to distinguish between
    // different types of write action (e.g. write, delete)
    opaAclChecker.checkPermissionInfo(
        user, c.getEnvironment().getRegion().getRegionInfo().getTable(), Action.WRITE);
  }

  @Override
  public Result preAppend(ObserverContext<RegionCoprocessorEnvironment> c, Append append)
      throws IOException {
    User user = getActiveUser(c);
    LOG.info("preAppend: user [{}]", user);

    opaAclChecker.checkPermissionInfo(
        user, c.getEnvironment().getRegion().getRegionInfo().getTable(), Action.WRITE);

    // as per default access controller
    return null;
  }

  @Override
  public void grant(
      RpcController controller,
      AccessControlProtos.GrantRequest request,
      RpcCallback<AccessControlProtos.GrantResponse> done) {}

  @Override
  public void revoke(
      RpcController controller,
      AccessControlProtos.RevokeRequest request,
      RpcCallback<AccessControlProtos.RevokeResponse> done) {}

  @Override
  public void getUserPermissions(
      RpcController controller,
      AccessControlProtos.GetUserPermissionsRequest request,
      RpcCallback<AccessControlProtos.GetUserPermissionsResponse> done) {}

  @Override
  public void checkPermissions(
      RpcController controller,
      AccessControlProtos.CheckPermissionsRequest request,
      RpcCallback<AccessControlProtos.CheckPermissionsResponse> done) {}

  @Override
  public void hasPermission(
      RpcController controller,
      AccessControlProtos.HasPermissionRequest request,
      RpcCallback<AccessControlProtos.HasPermissionResponse> done) {}

  /*********************************** Observer/Service Getters ***********************************/
  @Override
  public Optional<RegionObserver> getRegionObserver() {
    return Optional.of(this);
  }

  @Override
  public Optional<MasterObserver> getMasterObserver() {
    return Optional.of(this);
  }

  @Override
  public Optional<EndpointObserver> getEndpointObserver() {
    return Optional.of(this);
  }

  @Override
  public Optional<BulkLoadObserver> getBulkLoadObserver() {
    return Optional.of(this);
  }

  @Override
  public Optional<RegionServerObserver> getRegionServerObserver() {
    return Optional.of(this);
  }
}
