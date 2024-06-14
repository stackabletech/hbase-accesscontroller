package tech.stackable.hbase;

import com.google.common.collect.MapMaker;
import com.google.protobuf.Message;
import com.google.protobuf.RpcCallback;
import com.google.protobuf.RpcController;
import com.google.protobuf.Service;
import java.io.IOException;
import java.util.*;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.*;
import org.apache.hadoop.hbase.client.*;
import org.apache.hadoop.hbase.coprocessor.*;
import org.apache.hadoop.hbase.filter.ByteArrayComparable;
import org.apache.hadoop.hbase.ipc.RpcServer;
import org.apache.hadoop.hbase.protobuf.generated.AccessControlProtos;
import org.apache.hadoop.hbase.quotas.GlobalQuotaSettings;
import org.apache.hadoop.hbase.regionserver.*;
import org.apache.hadoop.hbase.regionserver.compactions.CompactionLifeCycleTracker;
import org.apache.hadoop.hbase.regionserver.compactions.CompactionRequest;
import org.apache.hadoop.hbase.replication.ReplicationEndpoint;
import org.apache.hadoop.hbase.replication.ReplicationPeerConfig;
import org.apache.hadoop.hbase.security.AccessDeniedException;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.UserProvider;
import org.apache.hadoop.hbase.security.access.AccessChecker;
import org.apache.hadoop.hbase.security.access.Permission;
import org.apache.hadoop.hbase.security.access.Permission.Action;
import org.apache.hadoop.hbase.security.access.UserPermission;
import org.apache.hadoop.hbase.util.Pair;
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

  private boolean authorizationEnabled;

  // Opa-related
  public static final String OPA_POLICY_URL_PROP = "hbase.security.authorization.opa.policy.url";
  public static final String OPA_POLICY_DRYRUN = "hbase.security.authorization.opa.policy.dryrun";
  public static final String OPA_POLICY_CACHE =
      "hbase.security.authorization.opa.policy.cache.active";
  public static final String OPA_POLICY_CACHE_TTL_SECONDS =
      "hbase.security.authorization.opa.policy.cache.seconds";
  public static final String OPA_POLICY_CACHE_TTL_SIZE =
      "hbase.security.authorization.opa.policy.cache.size";

  // Mapping of scanner instances to the user who created them
  private Map<InternalScanner, String> scannerOwners = new MapMaker().weakKeys().makeMap();

  @Override
  public void start(CoprocessorEnvironment env) {
    this.authorizationEnabled = AccessChecker.isAuthorizationSupported(env.getConfiguration());
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
  public void preCreateNamespace(
      ObserverContext<MasterCoprocessorEnvironment> c, NamespaceDescriptor ns) throws IOException {
    User user = getActiveUser(c);
    LOG.info("preCreateNamespace: user [{}]", user);
    opaAclChecker.checkPermissionInfo(user, ns.getName(), Action.ADMIN);
  }

  @Override
  public void preDeleteNamespace(ObserverContext<MasterCoprocessorEnvironment> c, String namespace)
      throws IOException {
    User user = getActiveUser(c);
    LOG.info("preDeleteNamespace: user [{}]", user);
    opaAclChecker.checkPermissionInfo(user, namespace, Action.ADMIN);
  }

  @Override
  public void preModifyNamespace(
      ObserverContext<MasterCoprocessorEnvironment> c, NamespaceDescriptor ns) throws IOException {
    User user = getActiveUser(c);
    LOG.info("preModifyNamespace: user [{}]", user);
    opaAclChecker.checkPermissionInfo(user, ns.getName(), Action.ADMIN);
  }

  @Override
  public void preGetNamespaceDescriptor(
      ObserverContext<MasterCoprocessorEnvironment> c, String namespace) throws IOException {
    User user = getActiveUser(c);
    LOG.info("preGetNamespaceDescriptor: user [{}]", user);
    opaAclChecker.checkPermissionInfo(user, namespace, Action.ADMIN);
  }

  @Override
  public void postListNamespaces(
      ObserverContext<MasterCoprocessorEnvironment> c, List<String> namespaces) throws IOException {
    User user = getActiveUser(c);
    /* always allow namespace listing */
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
  }

  @Override
  public void preEnableTable(ObserverContext<MasterCoprocessorEnvironment> c, TableName tableName)
      throws IOException {
    User user = getActiveUser(c);
    LOG.info("preEnableTable: user [{}]", user);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.CREATE);
  }

  @Override
  public void preDisableTable(ObserverContext<MasterCoprocessorEnvironment> c, TableName tableName)
      throws IOException {
    User user = getActiveUser(c);
    LOG.info("preDisableTable: user [{}]", user);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.CREATE);
  }

  @Override
  public void preGetOp(
      final ObserverContext<RegionCoprocessorEnvironment> c, final Get get, final List<Cell> result)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    // All users need read access to hbase:meta table.
    if (TableName.META_TABLE_NAME.equals(tableName)) {
      return;
    }
    LOG.info("preGetOp: user [{}] on table [{}] with get [{}]", user, tableName, get);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.READ);
  }

  @Override
  public boolean preExists(
      final ObserverContext<RegionCoprocessorEnvironment> c, final Get get, final boolean exists)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    // All users need read access to hbase:meta table.
    if (TableName.META_TABLE_NAME.equals(tableName)) {
      return exists;
    }
    LOG.info("preExists: user [{}] on table [{}] with get [{}]", user, tableName, get);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.READ);
    return exists;
  }

  @Override
  public void preScannerOpen(final ObserverContext<RegionCoprocessorEnvironment> c, final Scan scan)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    // All users need read access to hbase:meta table.
    if (TableName.META_TABLE_NAME.equals(tableName)) {
      return;
    }
    LOG.info("preScannerOpen: user [{}] on table [{}] with scan [{}]", user, tableName, scan);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.READ);
  }

  @Override
  public RegionScanner postScannerOpen(
      final ObserverContext<RegionCoprocessorEnvironment> c, final Scan scan, final RegionScanner s)
      throws IOException {
    User user = getActiveUser(c);
    if (user != null && user.getShortName() != null) {
      // TODO this uses the shortName. Is it possible for the same scanner to be used by
      // different users across principals who nevertheless have the same shortName? This
      // is augmented by a specific user check via OPA, so we may not need to track the
      // scanners at all.
      scannerOwners.put(s, user.getShortName());
    }
    return s;
  }

  @Override
  public boolean preScannerNext(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final InternalScanner s,
      final List<Result> result,
      final int limit,
      final boolean hasNext)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    // All users need read access to hbase:meta table.
    if (TableName.META_TABLE_NAME.equals(tableName)) {
      return hasNext;
    }
    LOG.info("preScannerNext: user [{}] on table [{}] with scan [{}]", user, tableName, s);

    requireScannerOwner(s);
    opaAclChecker.checkPermissionInfo(user, tableName, Action.READ);
    return hasNext;
  }

  @Override
  public void preScannerClose(
      final ObserverContext<RegionCoprocessorEnvironment> c, final InternalScanner s)
      throws AccessDeniedException {
    requireScannerOwner(s);
  }

  @Override
  public void postScannerClose(
      final ObserverContext<RegionCoprocessorEnvironment> c, final InternalScanner s) {
    scannerOwners.remove(s);
  }

  private void requireScannerOwner(InternalScanner s) throws AccessDeniedException {
    if (!RpcServer.isInRpcCallContext()) {
      return;
    }
    String requestUserName = RpcServer.getRequestUserName().orElse(null);
    String owner = scannerOwners.get(s);
    if (authorizationEnabled && owner != null && !owner.equals(requestUserName)) {
      throw new AccessDeniedException("User '" + requestUserName + "' is not the scanner owner!");
    }
  }

  @Override
  public void prePut(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final Put put,
      final WALEdit edit,
      final Durability durability)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.info("prePut: user [{}] on table [{}] with put [{}]", user, tableName, put);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);
  }

  @Override
  public void preDelete(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final Delete delete,
      final WALEdit edit,
      final Durability durability)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.info("preDelete: user [{}] on table [{}] with delete [{}]", user, tableName, delete);

    // the default access controller uses a second enum - OpType - to distinguish between
    // different types of write action (e.g. write, delete)
    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);
  }

  @Override
  public void postDelete(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final Delete delete,
      final WALEdit edit,
      final Durability durability) {
    // not needed as we do not use the ACL table
  }

  @Override
  public Result preAppend(ObserverContext<RegionCoprocessorEnvironment> c, Append append)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.info("preAppend: user [{}] on table [{}] with append [{}]", user, tableName, append);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);

    // as per default access controller
    return null;
  }

  @Override
  public void preBatchMutate(
      ObserverContext<RegionCoprocessorEnvironment> c,
      MiniBatchOperationInProgress<Mutation> miniBatchOp)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.info(
        "preBatchMutate: user [{}] on table [{}] with miniBatchOp [{}]",
        user,
        tableName,
        miniBatchOp);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);
  }

  @Override
  public void preOpen(ObserverContext<RegionCoprocessorEnvironment> c) throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.info("preOpen: user [{}] on table [{}]", user, tableName);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.ADMIN);
  }

  @Override
  public void postOpen(ObserverContext<RegionCoprocessorEnvironment> c) {
    // not needed as the ACL table is not used
  }

  @Override
  public void preTableFlush(
      final ObserverContext<MasterCoprocessorEnvironment> ctx, final TableName tableName)
      throws IOException {
    User user = getActiveUser(ctx);
    LOG.info("preTableFlush: user [{}] on table [{}]", user, tableName);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);
  }

  @Override
  public void preFlush(
      ObserverContext<RegionCoprocessorEnvironment> c, FlushLifeCycleTracker tracker)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.info("preFlush: user [{}] on table [{}]", user, tableName);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);
  }

  @Override
  public InternalScanner preCompact(
      ObserverContext<RegionCoprocessorEnvironment> c,
      Store store,
      InternalScanner scanner,
      ScanType scanType,
      CompactionLifeCycleTracker tracker,
      CompactionRequest request)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.info("preCompact: user [{}] on table [{}] for scanner [{}]", user, scanner);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);

    return scanner;
  }

  @Override
  public void preGetTableDescriptors(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      List<TableName> tableNamesList,
      List<TableDescriptor> descriptors,
      String regex) {
    // allow for all users
  }

  @Override
  public void postGetTableDescriptors(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      List<TableName> tableNamesList,
      List<TableDescriptor> descriptors,
      String regex) {
    // allow for all users
  }

  @Override
  public void postGetTableNames(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      List<TableDescriptor> descriptors,
      String regex) {
    // allow for all users
  }

  @Override
  public boolean preCheckAndPut(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final byte[] row,
      final byte[] family,
      final byte[] qualifier,
      final CompareOperator op,
      final ByteArrayComparable comparator,
      final Put put,
      final boolean result)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.info("preCheckAndPut: user [{}] on table [{}] for put [{}]", user, put);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);
    return result;
  }

  @Override
  public boolean preCheckAndPutAfterRowLock(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final byte[] row,
      final byte[] family,
      final byte[] qualifier,
      final CompareOperator opp,
      final ByteArrayComparable comparator,
      final Put put,
      final boolean result)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.info("preCheckAndPutAfterRowLock: user [{}] on table [{}] for put [{}]", user, put);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);
    return result;
  }

  @Override
  public boolean preCheckAndDelete(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final byte[] row,
      final byte[] family,
      final byte[] qualifier,
      final CompareOperator op,
      final ByteArrayComparable comparator,
      final Delete delete,
      final boolean result)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.info("preCheckAndDelete: user [{}] on table [{}] for delete [{}]", user, delete);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);
    return result;
  }

  @Override
  public boolean preCheckAndDeleteAfterRowLock(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final byte[] row,
      final byte[] family,
      final byte[] qualifier,
      final CompareOperator op,
      final ByteArrayComparable comparator,
      final Delete delete,
      final boolean result)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.info(
        "preCheckAndDeleteAfterRowLock: user [{}] on table [{}] for delete [{}]", user, delete);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);
    return result;
  }

  @Override
  public void postListNamespaceDescriptors(
      ObserverContext<MasterCoprocessorEnvironment> ctx, List<NamespaceDescriptor> descriptors) {
    // allow for all users
  }

  @Override
  public void preTruncateTable(
      ObserverContext<MasterCoprocessorEnvironment> c, final TableName tableName)
      throws IOException {
    User user = getActiveUser(c);
    LOG.info("preTruncateTable: user [{}] on table [{}]", user, tableName);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.CREATE);
  }

  @Override
  public void postTruncateTable(
      ObserverContext<MasterCoprocessorEnvironment> ctx, final TableName tableName)
      throws IOException {
    User user = getActiveUser(ctx);
    LOG.info("postTruncateTable: user [{}] on table [{}]", user, tableName);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.CREATE);
  }

  @Override
  public TableDescriptor preModifyTable(
      ObserverContext<MasterCoprocessorEnvironment> c,
      TableName tableName,
      TableDescriptor currentDesc,
      TableDescriptor newDesc)
      throws IOException {
    User user = getActiveUser(c);
    LOG.info("preModifyTable: user [{}] on table [{}]", user, tableName);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.CREATE);
    return currentDesc;
  }

  @Override
  public void postModifyTable(
      ObserverContext<MasterCoprocessorEnvironment> c,
      TableName tableName,
      final TableDescriptor htd)
      throws IOException {
    User user = getActiveUser(c);
    LOG.info("postModifyTable: user [{}] on table [{}]", user, tableName);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.CREATE);
  }

  @Override
  public Result preIncrement(
      final ObserverContext<RegionCoprocessorEnvironment> c, final Increment increment)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.info("preIncrement: user [{}] on table [{}]", user, tableName);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);
    // as per default controller
    return null;
  }

  @Override
  public List<Pair<Cell, Cell>> postIncrementBeforeWAL(
      ObserverContext<RegionCoprocessorEnvironment> ctx,
      Mutation mutation,
      List<Pair<Cell, Cell>> cellPairs) {
    // we have no ACL table so return as per the similar case in the default controller
    return cellPairs;
  }

  @Override
  public List<Pair<Cell, Cell>> postAppendBeforeWAL(
      ObserverContext<RegionCoprocessorEnvironment> ctx,
      Mutation mutation,
      List<Pair<Cell, Cell>> cellPairs) {
    // we have no ACL table so return as per the similar case in the default controller
    return cellPairs;
  }

  /*********************************** Will be deprecated in 4.0 ***********************************/

  @Override
  public void grant(
      RpcController controller,
      AccessControlProtos.GrantRequest request,
      RpcCallback<AccessControlProtos.GrantResponse> done) {
    LOG.debug(
        "grant for {}/{}", request.getUserPermission().getUser(), request.getUserPermission());
  }

  @Override
  public void revoke(
      RpcController controller,
      AccessControlProtos.RevokeRequest request,
      RpcCallback<AccessControlProtos.RevokeResponse> done) {
    LOG.debug(
        "revoke for {}/{}", request.getUserPermission().getUser(), request.getUserPermission());
  }

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

  /*********************************** Not implemented (yet) ***********************************/

  public String preModifyTableStoreFileTracker(
      ObserverContext<MasterCoprocessorEnvironment> c, TableName tableName, String dstSFT) {
    requirePermission(
        c, "modifyTableStoreFileTracker", tableName, null, null, Action.ADMIN, Action.CREATE);
    return dstSFT;
  }

  @Override
  public String preModifyColumnFamilyStoreFileTracker(
      ObserverContext<MasterCoprocessorEnvironment> c,
      TableName tableName,
      byte[] family,
      String dstSFT) {
    requirePermission(
        c,
        "modifyColumnFamilyStoreFileTracker",
        tableName,
        family,
        null,
        Action.ADMIN,
        Action.CREATE);
    return dstSFT;
  }

  @Override
  public void preMove(
      ObserverContext<MasterCoprocessorEnvironment> c,
      RegionInfo region,
      ServerName srcServer,
      ServerName destServer) {
    requirePermission(c, "move", region.getTable(), null, null, Action.ADMIN);
  }

  @Override
  public void preAssign(ObserverContext<MasterCoprocessorEnvironment> c, RegionInfo regionInfo) {
    requirePermission(c, "assign", regionInfo.getTable(), null, null, Action.ADMIN);
  }

  @Override
  public void preUnassign(ObserverContext<MasterCoprocessorEnvironment> c, RegionInfo regionInfo) {
    requirePermission(c, "unassign", regionInfo.getTable(), null, null, Action.ADMIN);
  }

  @Override
  public void preRegionOffline(
      ObserverContext<MasterCoprocessorEnvironment> c, RegionInfo regionInfo) {
    requirePermission(c, "regionOffline", regionInfo.getTable(), null, null, Action.ADMIN);
  }

  @Override
  public void preSnapshot(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final SnapshotDescription snapshot,
      final TableDescriptor hTableDescriptor) {
    requirePermission(
        ctx,
        "snapshot " + snapshot.getName(),
        hTableDescriptor.getTableName(),
        null,
        null,
        Permission.Action.ADMIN);
  }

  @Override
  public void preListSnapshot(
      ObserverContext<MasterCoprocessorEnvironment> ctx, final SnapshotDescription snapshot) {
    LOG.warn("preListSnapshot not yet implemented! Snapshot: {}", snapshot);
  }

  @Override
  public void preCloneSnapshot(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final SnapshotDescription snapshot,
      final TableDescriptor hTableDescriptor) {
    LOG.warn("preCloneSnapshot not yet implemented! Snapshot: {}", snapshot);
  }

  @Override
  public void preRestoreSnapshot(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final SnapshotDescription snapshot,
      final TableDescriptor hTableDescriptor) {
    LOG.warn("preRestoreSnapshot not yet implemented! Snapshot: {}", snapshot);
  }

  @Override
  public void preDeleteSnapshot(
      final ObserverContext<MasterCoprocessorEnvironment> ctx, final SnapshotDescription snapshot) {
    LOG.warn("preDeleteSnapshot not yet implemented! Snapshot: {}", snapshot);
  }

  @Override
  public void preSplitRegion(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final TableName tableName,
      final byte[] splitRow) {
    requirePermission(ctx, "split", tableName, null, null, Action.ADMIN);
  }

  @Override
  public void preBulkLoadHFile(
      ObserverContext<RegionCoprocessorEnvironment> ctx, List<Pair<byte[], String>> familyPaths) {
    LOG.warn("preBulkLoadHFile not implemented!");
  }

  @Override
  public void prePrepareBulkLoad(ObserverContext<RegionCoprocessorEnvironment> ctx) {
    LOG.warn("prePrepareBulkLoad not implemented!");
  }

  @Override
  public void preCleanupBulkLoad(ObserverContext<RegionCoprocessorEnvironment> ctx) {
    LOG.warn("preCleanupBulkLoad not implemented!");
  }

  @Override
  public Message preEndpointInvocation(
      ObserverContext<RegionCoprocessorEnvironment> ctx,
      Service service,
      String methodName,
      Message request) {
    LOG.warn("preEndpointInvocation not implemented! {}/{}", methodName, request);
    return request;
  }

  @Override
  public void postEndpointInvocation(
      ObserverContext<RegionCoprocessorEnvironment> ctx,
      Service service,
      String methodName,
      Message request,
      Message.Builder responseBuilder) {
    LOG.warn("postEndpointInvocation not implemented! {}/{}", methodName, request);
  }

  @Override
  public void preRequestLock(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      String namespace,
      TableName tableName,
      RegionInfo[] regionInfos,
      String description) {
    LOG.warn("preRequestLock not implemented! {}/{}", tableName, regionInfos);
  }

  @Override
  public void preLockHeartbeat(
      ObserverContext<MasterCoprocessorEnvironment> ctx, TableName tableName, String description) {
    LOG.warn("preLockHeartbeat not implemented! {}/{}", tableName, description);
  }

  @Override
  public void preSetUserQuota(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final String userName,
      final TableName tableName,
      final GlobalQuotaSettings quotas) {
    requirePermission(ctx, "setUserTableQuota", tableName, null, null, Action.ADMIN);
  }

  @Override
  public void preSetUserQuota(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final String userName,
      final String namespace,
      final GlobalQuotaSettings quotas) {
    requirePermission(ctx, "setUserNamespaceQuota", Action.ADMIN);
  }

  @Override
  public void preSetTableQuota(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final TableName tableName,
      final GlobalQuotaSettings quotas) {
    requirePermission(ctx, "setTableQuota", tableName, null, null, Action.ADMIN);
  }

  @Override
  public void preSetNamespaceQuota(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final String namespace,
      final GlobalQuotaSettings quotas) {
    requirePermission(ctx, "setNamespaceQuota", Action.ADMIN);
  }

  @Override
  public void preMergeRegions(
      final ObserverContext<MasterCoprocessorEnvironment> ctx, final RegionInfo[] regionsToMerge) {
    requirePermission(ctx, "mergeRegions", regionsToMerge[0].getTable(), null, null, Action.ADMIN);
  }

  @Override
  public void preGetUserPermissions(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      String userName,
      String namespace,
      TableName tableName,
      byte[] family,
      byte[] qualifier) {
    LOG.warn("preGetUserPermissions not implemented! {}/{}", userName, tableName);
  }

  public void requirePermission(ObserverContext<?> ctx, String request, Action perm) {
    LOG.warn("requirePermission not implemented! {}/{}", request, perm);
  }

  public void requirePermission(
      ObserverContext<?> ctx,
      String request,
      TableName tableName,
      byte[] family,
      byte[] qualifier,
      Action... permissions) {
    LOG.warn("requirePermission for table not implemented! {}/{}", tableName, permissions);
  }

  /*********** Not implemented (admin tasks coming from the Master or RegionServer) *************************/

  @Override
  public void preAbortProcedure(
      ObserverContext<MasterCoprocessorEnvironment> ctx, final long procId) {
    LOG.debug("preAbortProcedure not implemented!");
  }

  @Override
  public void postAbortProcedure(ObserverContext<MasterCoprocessorEnvironment> ctx) {
    // There is nothing to do at this time after the procedure abort request was sent.
  }

  @Override
  public void preGetProcedures(ObserverContext<MasterCoprocessorEnvironment> ctx) {
    LOG.debug("preGetProcedures not implemented!");
  }

  @Override
  public void preGetLocks(ObserverContext<MasterCoprocessorEnvironment> ctx) {
    LOG.debug("preGetLocks not implemented!");
  }

  @Override
  public void preSetSplitOrMergeEnabled(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final boolean newValue,
      final MasterSwitchType switchType) {
    LOG.debug("preSetSplitOrMergeEnabled not implemented!");
  }

  @Override
  public void preBalance(ObserverContext<MasterCoprocessorEnvironment> c, BalanceRequest request) {
    LOG.debug("preBalance not implemented!");
  }

  @Override
  public void preBalanceSwitch(ObserverContext<MasterCoprocessorEnvironment> c, boolean newValue) {
    LOG.debug("preBalanceSwitch not implemented!");
  }

  @Override
  public void preShutdown(ObserverContext<MasterCoprocessorEnvironment> c) {
    LOG.debug("preShutdown not implemented!");
  }

  @Override
  public void preStopMaster(ObserverContext<MasterCoprocessorEnvironment> c) {
    LOG.debug("preStopMaster not implemented! {}");
  }

  @Override
  public void postStartMaster(ObserverContext<MasterCoprocessorEnvironment> ctx) {
    LOG.debug("postStartMaster not implemented!");
  }

  @Override
  public void preClearDeadServers(ObserverContext<MasterCoprocessorEnvironment> ctx) {
    LOG.debug("preClearDeadServers not implemented!");
  }

  @Override
  public void preDecommissionRegionServers(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      List<ServerName> servers,
      boolean offload) {
    LOG.debug("preDecommissionRegionServers not implemented!");
  }

  @Override
  public void preListDecommissionedRegionServers(
      ObserverContext<MasterCoprocessorEnvironment> ctx) {
    LOG.debug("preListDecommissionedRegionServers not implemented!");
  }

  @Override
  public void preRecommissionRegionServer(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      ServerName server,
      List<byte[]> encodedRegionNames) {
    LOG.debug("preRecommissionRegionServer not implemented!");
  }

  @Override
  public void preStopRegionServer(ObserverContext<RegionServerCoprocessorEnvironment> ctx) {
    LOG.debug("preStopRegionServer not implemented!");
  }

  @Override
  public void preRollWALWriterRequest(ObserverContext<RegionServerCoprocessorEnvironment> ctx) {
    LOG.debug("preRollWALWriterRequest not implemented!");
  }

  @Override
  public void postRollWALWriterRequest(ObserverContext<RegionServerCoprocessorEnvironment> ctx) {
    // as per default access controller
  }

  @Override
  public void preSetUserQuota(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final String userName,
      final GlobalQuotaSettings quotas) {
    LOG.debug("preSetUserQuota not implemented!");
  }

  @Override
  public void preSetRegionServerQuota(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      final String regionServer,
      GlobalQuotaSettings quotas) {
    LOG.debug("preSetRegionServerQuota not implemented!");
  }

  @Override
  public ReplicationEndpoint postCreateReplicationEndPoint(
      ObserverContext<RegionServerCoprocessorEnvironment> ctx, ReplicationEndpoint endpoint) {
    return endpoint;
  }

  @Override
  public void preReplicateLogEntries(ObserverContext<RegionServerCoprocessorEnvironment> ctx) {
    LOG.debug("preReplicateLogEntries not implemented!");
  }

  @Override
  public void preClearCompactionQueues(ObserverContext<RegionServerCoprocessorEnvironment> ctx) {
    LOG.debug("preClearCompactionQueues not implemented!");
  }

  @Override
  public void preAddReplicationPeer(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      String peerId,
      ReplicationPeerConfig peerConfig) {
    LOG.debug("preAddReplicationPeer not implemented!");
  }

  @Override
  public void preRemoveReplicationPeer(
      final ObserverContext<MasterCoprocessorEnvironment> ctx, String peerId) {
    LOG.debug("preRemoveReplicationPeer not implemented!");
  }

  @Override
  public void preEnableReplicationPeer(
      final ObserverContext<MasterCoprocessorEnvironment> ctx, String peerId) {
    LOG.debug("preEnableReplicationPeer not implemented!");
  }

  @Override
  public void preDisableReplicationPeer(
      final ObserverContext<MasterCoprocessorEnvironment> ctx, String peerId) {
    LOG.debug("preDisableReplicationPeer not implemented!");
  }

  @Override
  public void preGetReplicationPeerConfig(
      final ObserverContext<MasterCoprocessorEnvironment> ctx, String peerId) {
    LOG.debug("preGetReplicationPeerConfig not implemented!");
  }

  @Override
  public void preUpdateReplicationPeerConfig(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      String peerId,
      ReplicationPeerConfig peerConfig) {
    LOG.debug("preUpdateReplicationPeerConfig not implemented!");
  }

  @Override
  public void preListReplicationPeers(
      final ObserverContext<MasterCoprocessorEnvironment> ctx, String regex) {
    LOG.debug("preListReplicationPeers not implemented!");
  }

  @Override
  public void preExecuteProcedures(ObserverContext<RegionServerCoprocessorEnvironment> ctx) {
    LOG.debug("preExecuteProcedures not implemented!");
  }

  @Override
  public void preSwitchRpcThrottle(
      ObserverContext<MasterCoprocessorEnvironment> ctx, boolean enable) {
    LOG.debug("preSwitchRpcThrottle not implemented!");
  }

  @Override
  public void preIsRpcThrottleEnabled(ObserverContext<MasterCoprocessorEnvironment> ctx) {
    LOG.debug("preIsRpcThrottleEnabled not implemented!");
  }

  @Override
  public void preSwitchExceedThrottleQuota(
      ObserverContext<MasterCoprocessorEnvironment> ctx, boolean enable) {
    LOG.debug("preSwitchExceedThrottleQuota not implemented!");
  }

  @Override
  public void preGrant(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      UserPermission userPermission,
      boolean mergeExistingPermissions) {
    LOG.debug("preGrant not implemented!");
  }

  @Override
  public void preRevoke(
      ObserverContext<MasterCoprocessorEnvironment> ctx, UserPermission userPermission) {
    LOG.debug("preRevoke not implemented!");
  }

  @Override
  public void preHasUserPermissions(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      String userName,
      List<Permission> permissions) {
    LOG.debug("preHasUserPermissions not implemented!");
  }

  @Override
  public void preClearRegionBlockCache(ObserverContext<RegionServerCoprocessorEnvironment> ctx) {
    LOG.debug("preClearRegionBlockCache not implemented!");
  }

  @Override
  public void preUpdateRegionServerConfiguration(
      ObserverContext<RegionServerCoprocessorEnvironment> ctx, Configuration preReloadConf) {
    LOG.debug("preUpdateRegionServerConfiguration not implemented!");
  }

  @Override
  public void preUpdateMasterConfiguration(
      ObserverContext<MasterCoprocessorEnvironment> ctx, Configuration preReloadConf) {
    LOG.debug("preUpdateMasterConfiguration not implemented!");
  }
}
