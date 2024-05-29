package tech.stackable.hbase;

import com.google.common.collect.Lists;
import com.google.common.collect.MapMaker;
import com.google.common.collect.Maps;
import java.io.IOException;
import java.security.PrivilegedExceptionAction;
import java.util.*;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.*;
import org.apache.hadoop.hbase.client.*;
import org.apache.hadoop.hbase.coprocessor.*;
import org.apache.hadoop.hbase.filter.ByteArrayComparable;
import org.apache.hadoop.hbase.filter.Filter;
import org.apache.hadoop.hbase.filter.FilterList;
import org.apache.hadoop.hbase.ipc.RpcServer;
import org.apache.hadoop.hbase.master.MasterServices;
import org.apache.hadoop.hbase.regionserver.*;
import org.apache.hadoop.hbase.security.AccessDeniedException;
import org.apache.hadoop.hbase.security.Superusers;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.UserProvider;
import org.apache.hadoop.hbase.security.access.*;
import org.apache.hadoop.hbase.security.access.Permission.Action;
import org.apache.hadoop.hbase.snapshot.SnapshotDescriptionUtils;
import org.apache.hadoop.hbase.util.*;
import org.apache.hadoop.hbase.wal.WALEdit;
import org.apache.hbase.thirdparty.com.google.common.collect.ImmutableSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OpenPolicyAgentAccessController extends AccessController {

  private static final Logger LOG = LoggerFactory.getLogger(OpenPolicyAgentAccessController.class);
  private OpenPolicyAgentAccessChecker accessChecker;

  private static final String CHECK_COVERING_PERM = "check_covering_perm";
  private static final String TAG_CHECK_PASSED = "tag_check_passed";
  private static final byte[] TRUE = Bytes.toBytes(true);

  private Map<InternalScanner, String> scannerOwners = new MapMaker().weakKeys().makeMap();
  private UserProvider userProvider;

  // TODO check where set
  private boolean authorizationEnabled;
  private volatile boolean aclTabAvailable = false;
  private boolean cellFeaturesEnabled;
  private boolean compatibleEarlyTermination;

  @Override
  public void start(CoprocessorEnvironment env) throws IOException {
    super.start(env);

    if (env instanceof MasterCoprocessorEnvironment) {
      MasterCoprocessorEnvironment mEnv = (MasterCoprocessorEnvironment) env;
      if (mEnv instanceof HasMasterServices) {
        MasterServices masterServices = ((HasMasterServices) mEnv).getMasterServices();
        accessChecker = new OpenPolicyAgentAccessChecker(masterServices.getConfiguration());
      }
    } else if (env instanceof RegionServerCoprocessorEnvironment) {
      RegionServerCoprocessorEnvironment rsEnv = (RegionServerCoprocessorEnvironment) env;
      if (rsEnv instanceof HasRegionServerServices) {
        RegionServerServices rsServices =
            ((HasRegionServerServices) rsEnv).getRegionServerServices();
        accessChecker = new OpenPolicyAgentAccessChecker(rsServices.getConfiguration());
      }
    } else if (env instanceof RegionCoprocessorEnvironment) {
      RegionCoprocessorEnvironment regionEnv = (RegionCoprocessorEnvironment) env;
      if (regionEnv instanceof HasRegionServerServices) {
        RegionServerServices rsServices =
            ((HasRegionServerServices) regionEnv).getRegionServerServices();
        accessChecker = new OpenPolicyAgentAccessChecker(rsServices.getConfiguration());
      }
    }
    // set the user-provider.
    this.userProvider = UserProvider.instantiate(env.getConfiguration());
  }

  @Override
  public void requireAccess(
      ObserverContext<?> ctx, String request, TableName tableName, Action... permissions)
      throws IOException {
    accessChecker.requireAccess(getActiveUser(ctx), request, tableName, permissions);
  }

  @Override
  public void requirePermission(ObserverContext<?> ctx, String request, Action perm)
      throws IOException {
    accessChecker.requirePermission(getActiveUser(ctx), request, null, perm);
  }

  @Override
  public void requireGlobalPermission(
      ObserverContext<?> ctx,
      String request,
      Action perm,
      TableName tableName,
      Map<byte[], ? extends Collection<byte[]>> familyMap)
      throws IOException {
    accessChecker.requireGlobalPermission(
        getActiveUser(ctx), request, perm, tableName, familyMap, null);
  }

  @Override
  public void requireGlobalPermission(
      ObserverContext<?> ctx, String request, Action perm, String namespace) throws IOException {
    accessChecker.requireGlobalPermission(getActiveUser(ctx), request, perm, namespace);
  }

  @Override
  public void requireNamespacePermission(
      ObserverContext<?> ctx, String request, String namespace, Action... permissions)
      throws IOException {
    accessChecker.requireNamespacePermission(
        getActiveUser(ctx), request, namespace, null, permissions);
  }

  @Override
  public void requireNamespacePermission(
      ObserverContext<?> ctx,
      String request,
      String namespace,
      TableName tableName,
      Map<byte[], ? extends Collection<byte[]>> familyMap,
      Action... permissions)
      throws IOException {
    accessChecker.requireNamespacePermission(
        getActiveUser(ctx), request, namespace, tableName, familyMap, permissions);
  }

  @Override
  public void requirePermission(
      ObserverContext<?> ctx,
      String request,
      TableName tableName,
      byte[] family,
      byte[] qualifier,
      Action... permissions)
      throws IOException {
    accessChecker.requirePermission(
        getActiveUser(ctx), request, tableName, family, qualifier, null, permissions);
  }

  @Override
  public void requireTablePermission(
      ObserverContext<?> ctx,
      String request,
      TableName tableName,
      byte[] family,
      byte[] qualifier,
      Action... permissions)
      throws IOException {
    accessChecker.requireTablePermission(
        getActiveUser(ctx), request, tableName, family, qualifier, permissions);
  }

  @Override
  public void checkLockPermissions(
      ObserverContext<?> ctx,
      String namespace,
      TableName tableName,
      RegionInfo[] regionInfos,
      String reason)
      throws IOException {
    accessChecker.checkLockPermissions(
        getActiveUser(ctx), namespace, tableName, regionInfos, reason);
  }

  @Override
  public void postCompletedCreateTableAction(
      final ObserverContext<MasterCoprocessorEnvironment> c,
      final TableDescriptor desc,
      final RegionInfo[] regions)
      throws IOException {
    // When AC is used, it should be configured as the 1st CP.
    // In Master, the table operations like create, are handled by a Thread pool but the max size
    // for this pool is 1. So if multiple CPs create tables on startup, these creations will happen
    // sequentially only.
    // Related code in HMaster#startServiceThreads
    // {code}
    // // We depend on there being only one instance of this executor running
    // // at a time. To do concurrency, would need fencing of enable/disable of
    // // tables.
    // this.service.startExecutorService(ExecutorType.MASTER_TABLE_OPERATIONS, 1);
    // {code}
    // In future if we change this pool to have more threads, then there is a chance for thread,
    // creating acl table, getting delayed and by that time another table creation got over and
    // this hook is getting called. In such a case, we will need a wait logic here which will
    // wait till the acl table is created.
    if (PermissionStorage.ACL_TABLE_NAME.equals(desc.getTableName())) {
      this.aclTabAvailable = true;
    } else if (!(TableName.NAMESPACE_TABLE_NAME.equals(desc.getTableName()))) {
      if (!aclTabAvailable) {
        LOG.warn(
            "Not adding owner permission for table "
                + desc.getTableName()
                + ". "
                + PermissionStorage.ACL_TABLE_NAME
                + " is not yet created. "
                + getClass().getSimpleName()
                + " should be configured as the first Coprocessor");
      } else {
        String owner = desc.getOwnerString();
        // default the table owner to current user, if not specified.
        if (owner == null) owner = getActiveUser(c).getShortName();
        final UserPermission userPermission =
            new UserPermission(
                owner,
                Permission.newBuilder(desc.getTableName()).withActions(Action.values()).build());
        // switch to the real hbase master user for doing the RPC on the ACL table
        User.runAsLoginUser(
            new PrivilegedExceptionAction<Void>() {
              @Override
              public Void run() throws Exception {
                try (Table table =
                    c.getEnvironment().getConnection().getTable(PermissionStorage.ACL_TABLE_NAME)) {
                  PermissionStorage.addUserPermission(
                      c.getEnvironment().getConfiguration(), userPermission, table, false);
                }
                return null;
              }
            });
      }
    }
  }

  @Override
  public void postModifyTable(
      ObserverContext<MasterCoprocessorEnvironment> c,
      TableName tableName,
      final TableDescriptor htd)
      throws IOException {
    final Configuration conf = c.getEnvironment().getConfiguration();
    // default the table owner to current user, if not specified.
    final String owner =
        (htd.getOwnerString() != null) ? htd.getOwnerString() : getActiveUser(c).getShortName();
    User.runAsLoginUser(
        new PrivilegedExceptionAction<Void>() {
          @Override
          public Void run() throws Exception {
            UserPermission userperm =
                new UserPermission(
                    owner,
                    Permission.newBuilder(htd.getTableName()).withActions(Action.values()).build());
            try (Table table =
                c.getEnvironment().getConnection().getTable(PermissionStorage.ACL_TABLE_NAME)) {
              PermissionStorage.addUserPermission(conf, userperm, table, false);
            }
            return null;
          }
        });
  }

  @Override
  public void preGetLocks(ObserverContext<MasterCoprocessorEnvironment> ctx) throws IOException {
    User user = getActiveUser(ctx);
    accessChecker.requirePermission(user, "getLocks", null, Action.ADMIN);
  }

  @Override
  public void preListSnapshot(
      ObserverContext<MasterCoprocessorEnvironment> ctx, final SnapshotDescription snapshot)
      throws IOException {
    User user = getActiveUser(ctx);
    if (SnapshotDescriptionUtils.isSnapshotOwner(snapshot, user)) {
      // list it, if user is the owner of snapshot
      AuthResult result =
          AuthResult.allow(
              "listSnapshot " + snapshot.getName(),
              "Snapshot owner check allowed",
              user,
              null,
              null,
              null);
      AccessChecker.logResult(result);
    } else {
      accessChecker.requirePermission(
          user, "listSnapshot " + snapshot.getName(), null, Action.ADMIN);
    }
  }

  @Override
  public void preCloneSnapshot(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final SnapshotDescription snapshot,
      final TableDescriptor hTableDescriptor)
      throws IOException {
    User user = getActiveUser(ctx);
    if (SnapshotDescriptionUtils.isSnapshotOwner(snapshot, user)
        && hTableDescriptor.getTableName().getNameAsString().equals(snapshot.getTable())) {
      // Snapshot owner is allowed to create a table with the same name as the snapshot he took
      AuthResult result =
          AuthResult.allow(
              "cloneSnapshot " + snapshot.getName(),
              "Snapshot owner check allowed",
              user,
              null,
              hTableDescriptor.getTableName(),
              null);
      AccessChecker.logResult(result);
    } else if (SnapshotDescriptionUtils.isSnapshotOwner(snapshot, user)) {
      requireNamespacePermission(
          ctx,
          "cloneSnapshot",
          hTableDescriptor.getTableName().getNamespaceAsString(),
          Action.ADMIN);
    } else {
      accessChecker.requirePermission(
          user, "cloneSnapshot " + snapshot.getName(), null, Action.ADMIN);
    }
  }

  @Override
  public void preRestoreSnapshot(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final SnapshotDescription snapshot,
      final TableDescriptor hTableDescriptor)
      throws IOException {
    User user = getActiveUser(ctx);
    if (SnapshotDescriptionUtils.isSnapshotOwner(snapshot, user)) {
      accessChecker.requirePermission(
          user,
          "restoreSnapshot " + snapshot.getName(),
          hTableDescriptor.getTableName(),
          null,
          null,
          null,
          Permission.Action.ADMIN);
    } else {
      accessChecker.requirePermission(
          user, "restoreSnapshot " + snapshot.getName(), null, Action.ADMIN);
    }
  }

  @Override
  public void preDeleteSnapshot(
      final ObserverContext<MasterCoprocessorEnvironment> ctx, final SnapshotDescription snapshot)
      throws IOException {
    User user = getActiveUser(ctx);
    if (SnapshotDescriptionUtils.isSnapshotOwner(snapshot, user)) {
      // Snapshot owner is allowed to delete the snapshot
      AuthResult result =
          AuthResult.allow(
              "deleteSnapshot " + snapshot.getName(),
              "Snapshot owner check allowed",
              user,
              null,
              null,
              null);
      AccessChecker.logResult(result);
    } else {
      accessChecker.requirePermission(
          user, "deleteSnapshot " + snapshot.getName(), null, Action.ADMIN);
    }
  }

  @Override
  public void postListNamespaceDescriptors(
      ObserverContext<MasterCoprocessorEnvironment> ctx, List<NamespaceDescriptor> descriptors)
      throws IOException {
    // Retains only those which passes authorization checks, as the checks weren't done as part
    // of preGetTableDescriptors.
    Iterator<NamespaceDescriptor> itr = descriptors.iterator();
    User user = getActiveUser(ctx);
    while (itr.hasNext()) {
      NamespaceDescriptor desc = itr.next();
      try {
        accessChecker.requireNamespacePermission(
            user, "listNamespaces", desc.getName(), null, Action.ADMIN);
      } catch (AccessDeniedException e) {
        itr.remove();
      }
    }
  }

  @Override
  public void preOpen(ObserverContext<RegionCoprocessorEnvironment> c) throws IOException {
    RegionCoprocessorEnvironment env = c.getEnvironment();
    final Region region = env.getRegion();
    if (region == null) {
      LOG.error("NULL region from RegionCoprocessorEnvironment in preOpen()");
    } else {
      RegionInfo regionInfo = region.getRegionInfo();
      if (regionInfo.getTable().isSystemTable()) {
        checkSystemOrSuperUser(getActiveUser(c));
      } else {
        requirePermission(c, "preOpen", Action.ADMIN);
      }
    }
  }

  private void checkSystemOrSuperUser(User activeUser) throws IOException {
    // No need to check if we're not going to throw
    if (!authorizationEnabled) {
      return;
    }
    if (!Superusers.isSuperUser(activeUser)) {
      throw new AccessDeniedException(
          "User '"
              + (activeUser != null ? activeUser.getShortName() : "null")
              + "' is not system or super user.");
    }
  }

  private void internalPreRead(
      final ObserverContext<RegionCoprocessorEnvironment> c, final Query query, OpType opType)
      throws IOException {
    Filter filter = query.getFilter();
    // Don't wrap an OpenPolicyAgentAccessControlFilter
    if (filter != null && filter instanceof OpenPolicyAgentAccessControlFilter) {
      return;
    }
    User user = getActiveUser(c);
    RegionCoprocessorEnvironment env = c.getEnvironment();
    Map<byte[], ? extends Collection<byte[]>> families = null;
    switch (opType) {
      case GET:
      case EXISTS:
        families = ((Get) query).getFamilyMap();
        break;
      case SCAN:
        families = ((Scan) query).getFamilyMap();
        break;
      default:
        throw new RuntimeException("Unhandled operation " + opType);
    }
    AuthResult authResult = permissionGranted(opType, user, env, families, Action.READ);
    Region region = getRegion(env);
    TableName table = getTableName(region);
    Map<ByteRange, Integer> cfVsMaxVersions = Maps.newHashMap();
    for (ColumnFamilyDescriptor hcd : region.getTableDescriptor().getColumnFamilies()) {
      cfVsMaxVersions.put(new SimpleMutableByteRange(hcd.getName()), hcd.getMaxVersions());
    }
    if (!authResult.isAllowed()) {
      // New behavior: Any access we might be granted is more fine-grained
      // than whole table or CF. Simply inject a filter and return what is
      // allowed. We will not throw an AccessDeniedException. This is a
      // behavioral change since 0.96.
      authResult.setAllowed(true);
      authResult.setReason("Access allowed with filter");
      // Only wrap the filter if we are enforcing authorizations
      if (authorizationEnabled) {
        Filter ourFilter =
            new OpenPolicyAgentAccessControlFilter(
                getAuthManager(),
                user,
                table,
                OpenPolicyAgentAccessControlFilter.Strategy.CHECK_CELL_DEFAULT,
                cfVsMaxVersions);
        // wrap any existing filter
        if (filter != null) {
          ourFilter =
              new FilterList(
                  FilterList.Operator.MUST_PASS_ALL, Lists.newArrayList(ourFilter, filter));
        }
        switch (opType) {
          case GET:
          case EXISTS:
            ((Get) query).setFilter(ourFilter);
            break;
          case SCAN:
            ((Scan) query).setFilter(ourFilter);
            break;
          default:
            throw new RuntimeException("Unhandled operation " + opType);
        }
      }
    }

    AccessChecker.logResult(authResult);
    if (authorizationEnabled && !authResult.isAllowed()) {
      throw new AccessDeniedException(
          "Insufficient permissions for user '"
              + (user != null ? user.getShortName() : "null")
              + "' (table="
              + table
              + ", action=READ)");
    }
  }

  private boolean hasFamilyQualifierPermission(
      User user,
      Action perm,
      RegionCoprocessorEnvironment env,
      Map<byte[], ? extends Collection<byte[]>> familyMap)
      throws IOException {
    RegionInfo hri = env.getRegion().getRegionInfo();
    TableName tableName = hri.getTable();

    if (user == null) {
      return false;
    }

    if (familyMap != null && familyMap.size() > 0) {
      // at least one family must be allowed
      for (Map.Entry<byte[], ? extends Collection<byte[]>> family : familyMap.entrySet()) {
        if (family.getValue() != null && !family.getValue().isEmpty()) {
          for (byte[] qualifier : family.getValue()) {
            if (getAuthManager()
                .authorizeUserTable(user, tableName, family.getKey(), qualifier, perm)) {
              return true;
            }
          }
        } else {
          if (getAuthManager().authorizeUserFamily(user, tableName, family.getKey(), perm)) {
            return true;
          }
        }
      }
    } else if (LOG.isDebugEnabled()) {
      LOG.debug("Empty family map passed for permission check");
    }

    return false;
  }

  private AuthResult permissionGranted(
      OpType opType,
      User user,
      RegionCoprocessorEnvironment e,
      Map<byte[], ? extends Collection<?>> families,
      Action... actions) {
    AuthResult result = null;
    for (Action action : actions) {
      result =
          accessChecker.permissionGranted(
              opType.toString(), user, action, e.getRegion().getRegionInfo().getTable(), families);
      if (!result.isAllowed()) {
        return result;
      }
    }
    return result;
  }

  private Region getRegion(RegionCoprocessorEnvironment e) {
    return e.getRegion();
  }

  private TableName getTableName(RegionCoprocessorEnvironment e) {
    Region region = e.getRegion();
    if (region != null) {
      return getTableName(region);
    }
    return null;
  }

  private TableName getTableName(Region region) {
    RegionInfo regionInfo = region.getRegionInfo();
    if (regionInfo != null) {
      return regionInfo.getTable();
    }
    return null;
  }

  private void checkForReservedTagPresence(User user, Mutation m) throws IOException {
    // No need to check if we're not going to throw
    if (!authorizationEnabled) {
      m.setAttribute(TAG_CHECK_PASSED, TRUE);
      return;
    }
    // Superusers are allowed to store cells unconditionally.
    if (Superusers.isSuperUser(user)) {
      m.setAttribute(TAG_CHECK_PASSED, TRUE);
      return;
    }
    // We already checked (prePut vs preBatchMutation)
    if (m.getAttribute(TAG_CHECK_PASSED) != null) {
      return;
    }
    for (CellScanner cellScanner = m.cellScanner(); cellScanner.advance(); ) {
      Iterator<Tag> tagsItr = PrivateCellUtil.tagsIterator(cellScanner.current());
      while (tagsItr.hasNext()) {
        if (tagsItr.next().getType() == PermissionStorage.ACL_TAG_TYPE) {
          throw new AccessDeniedException("Mutation contains cell with reserved type tag");
        }
      }
    }
    m.setAttribute(TAG_CHECK_PASSED, TRUE);
  }

  private enum OpType {
    GET("get"),
    EXISTS("exists"),
    SCAN("scan"),
    PUT("put"),
    DELETE("delete"),
    CHECK_AND_PUT("checkAndPut"),
    CHECK_AND_DELETE("checkAndDelete"),
    APPEND("append"),
    INCREMENT("increment");

    private String type;

    private OpType(String type) {
      this.type = type;
    }

    @Override
    public String toString() {
      return type;
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
    checkForReservedTagPresence(user, put);

    // Require WRITE permission to the table, CF, or top visible value, if any.
    // NOTE: We don't need to check the permissions for any earlier Puts
    // because we treat the ACLs in each Put as timestamped like any other
    // HBase value. A new ACL in a new Put applies to that Put. It doesn't
    // change the ACL of any previous Put. This allows simple evolution of
    // security policy over time without requiring expensive updates.
    RegionCoprocessorEnvironment env = c.getEnvironment();
    Map<byte[], ? extends Collection<Cell>> families = put.getFamilyCellMap();
    AuthResult authResult = permissionGranted(OpType.PUT, user, env, families, Action.WRITE);
    AccessChecker.logResult(authResult);
    if (!authResult.isAllowed()) {
      if (cellFeaturesEnabled && !compatibleEarlyTermination) {
        put.setAttribute(CHECK_COVERING_PERM, TRUE);
      } else if (authorizationEnabled) {
        throw new AccessDeniedException("Insufficient permissions " + authResult.toContextString());
      }
    }

    // Add cell ACLs from the operation to the cells themselves
    byte[] bytes = put.getAttribute(AccessControlConstants.OP_ATTRIBUTE_ACL);
    if (bytes != null) {
      if (cellFeaturesEnabled) {
        addCellPermissions(bytes, put.getFamilyCellMap());
      } else {
        throw new DoNotRetryIOException("Cell ACLs cannot be persisted");
      }
    }
  }

  private static void addCellPermissions(final byte[] perms, Map<byte[], List<Cell>> familyMap) {
    // Iterate over the entries in the familyMap, replacing the cells therein
    // with new cells including the ACL data
    for (Map.Entry<byte[], List<Cell>> e : familyMap.entrySet()) {
      List<Cell> newCells =
          org.apache.hbase.thirdparty.com.google.common.collect.Lists.newArrayList();
      for (Cell cell : e.getValue()) {
        // Prepend the supplied perms in a new ACL tag to an update list of tags for the cell
        List<Tag> tags = new ArrayList<>();
        tags.add(new ArrayBackedTag(PermissionStorage.ACL_TAG_TYPE, perms));
        Iterator<Tag> tagIterator = PrivateCellUtil.tagsIterator(cell);
        while (tagIterator.hasNext()) {
          tags.add(tagIterator.next());
        }
        newCells.add(PrivateCellUtil.createCell(cell, tags));
      }
      // This is supposed to be safe, won't CME
      e.setValue(newCells);
    }
  }

  @Override
  public void preDelete(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final Delete delete,
      final WALEdit edit,
      final Durability durability)
      throws IOException {
    // An ACL on a delete is useless, we shouldn't allow it
    if (delete.getAttribute(AccessControlConstants.OP_ATTRIBUTE_ACL) != null) {
      throw new DoNotRetryIOException("ACL on delete has no effect: " + delete.toString());
    }
    // Require WRITE permissions on all cells covered by the delete. Unlike
    // for Puts we need to check all visible prior versions, because a major
    // compaction could remove them. If the user doesn't have permission to
    // overwrite any of the visible versions ('visible' defined as not covered
    // by a tombstone already) then we have to disallow this operation.
    RegionCoprocessorEnvironment env = c.getEnvironment();
    Map<byte[], ? extends Collection<Cell>> families = delete.getFamilyCellMap();
    User user = getActiveUser(c);
    AuthResult authResult = permissionGranted(OpType.DELETE, user, env, families, Action.WRITE);
    AccessChecker.logResult(authResult);
    if (!authResult.isAllowed()) {
      if (cellFeaturesEnabled && !compatibleEarlyTermination) {
        delete.setAttribute(CHECK_COVERING_PERM, TRUE);
      } else if (authorizationEnabled) {
        throw new AccessDeniedException("Insufficient permissions " + authResult.toContextString());
      }
    }
  }

  @Override
  public void preBatchMutate(
      ObserverContext<RegionCoprocessorEnvironment> c,
      MiniBatchOperationInProgress<Mutation> miniBatchOp)
      throws IOException {
    if (cellFeaturesEnabled && !compatibleEarlyTermination) {
      TableName table = c.getEnvironment().getRegion().getRegionInfo().getTable();
      User user = getActiveUser(c);
      for (int i = 0; i < miniBatchOp.size(); i++) {
        Mutation m = miniBatchOp.getOperation(i);
        if (m.getAttribute(CHECK_COVERING_PERM) != null) {
          // We have a failure with table, cf and q perm checks and now giving a chance for cell
          // perm check
          OpType opType;
          long timestamp;
          if (m instanceof Put) {
            checkForReservedTagPresence(user, m);
            opType = OpType.PUT;
            timestamp = m.getTimestamp();
          } else if (m instanceof Delete) {
            opType = OpType.DELETE;
            timestamp = m.getTimestamp();
          } else if (m instanceof Increment) {
            opType = OpType.INCREMENT;
            timestamp = ((Increment) m).getTimeRange().getMax();
          } else if (m instanceof Append) {
            opType = OpType.APPEND;
            timestamp = ((Append) m).getTimeRange().getMax();
          } else {
            // If the operation type is not Put/Delete/Increment/Append, do nothing
            continue;
          }
          AuthResult authResult = null;
          if (checkCoveringPermission(
              user,
              opType,
              c.getEnvironment(),
              m.getRow(),
              m.getFamilyCellMap(),
              timestamp,
              Action.WRITE)) {
            authResult =
                AuthResult.allow(
                    opType.toString(),
                    "Covering cell set",
                    user,
                    Action.WRITE,
                    table,
                    m.getFamilyCellMap());
          } else {
            authResult =
                AuthResult.deny(
                    opType.toString(),
                    "Covering cell set",
                    user,
                    Action.WRITE,
                    table,
                    m.getFamilyCellMap());
          }
          AccessChecker.logResult(authResult);
          if (authorizationEnabled && !authResult.isAllowed()) {
            throw new AccessDeniedException(
                "Insufficient permissions " + authResult.toContextString());
          }
        }
      }
    }
  }

  private boolean checkCoveringPermission(
      User user,
      OpType request,
      RegionCoprocessorEnvironment e,
      byte[] row,
      Map<byte[], ? extends Collection<?>> familyMap,
      long opTs,
      Action... actions)
      throws IOException {
    if (!cellFeaturesEnabled) {
      return false;
    }
    long cellGrants = 0;
    long latestCellTs = 0;
    Get get = new Get(row);
    // Only in case of Put/Delete op, consider TS within cell (if set for individual cells).
    // When every cell, within a Mutation, can be linked with diff TS we can not rely on only one
    // version. We have to get every cell version and check its TS against the TS asked for in
    // Mutation and skip those Cells which is outside this Mutation TS.In case of Put, we have to
    // consider only one such passing cell. In case of Delete we have to consider all the cell
    // versions under this passing version. When Delete Mutation contains columns which are a
    // version delete just consider only one version for those column cells.
    boolean considerCellTs = (request == OpType.PUT || request == OpType.DELETE);
    if (considerCellTs) {
      get.setMaxVersions();
    } else {
      get.setMaxVersions(1);
    }
    boolean diffCellTsFromOpTs = false;
    for (Map.Entry<byte[], ? extends Collection<?>> entry : familyMap.entrySet()) {
      byte[] col = entry.getKey();
      // TODO: HBASE-7114 could possibly unify the collection type in family
      // maps so we would not need to do this
      if (entry.getValue() instanceof Set) {
        Set<byte[]> set = (Set<byte[]>) entry.getValue();
        if (set == null || set.isEmpty()) {
          get.addFamily(col);
        } else {
          for (byte[] qual : set) {
            get.addColumn(col, qual);
          }
        }
      } else if (entry.getValue() instanceof List) {
        List<Cell> list = (List<Cell>) entry.getValue();
        if (list == null || list.isEmpty()) {
          get.addFamily(col);
        } else {
          // In case of family delete, a Cell will be added into the list with Qualifier as null.
          for (Cell cell : list) {
            if (cell.getQualifierLength() == 0
                && (cell.getTypeByte() == KeyValue.Type.DeleteFamily.getCode()
                    || cell.getTypeByte() == KeyValue.Type.DeleteFamilyVersion.getCode())) {
              get.addFamily(col);
            } else {
              get.addColumn(col, CellUtil.cloneQualifier(cell));
            }
            if (considerCellTs) {
              long cellTs = cell.getTimestamp();
              latestCellTs = Math.max(latestCellTs, cellTs);
              diffCellTsFromOpTs = diffCellTsFromOpTs || (opTs != cellTs);
            }
          }
        }
      } else if (entry.getValue() == null) {
        get.addFamily(col);
      } else {
        throw new RuntimeException(
            "Unhandled collection type " + entry.getValue().getClass().getName());
      }
    }
    // We want to avoid looking into the future. So, if the cells of the
    // operation specify a timestamp, or the operation itself specifies a
    // timestamp, then we use the maximum ts found. Otherwise, we bound
    // the Get to the current server time. We add 1 to the timerange since
    // the upper bound of a timerange is exclusive yet we need to examine
    // any cells found there inclusively.
    long latestTs = Math.max(opTs, latestCellTs);
    if (latestTs == 0 || latestTs == HConstants.LATEST_TIMESTAMP) {
      latestTs = EnvironmentEdgeManager.currentTime();
    }
    get.setTimeRange(0, latestTs + 1);
    // In case of Put operation we set to read all versions. This was done to consider the case
    // where columns are added with TS other than the Mutation TS. But normally this wont be the
    // case with Put. There no need to get all versions but get latest version only.
    if (!diffCellTsFromOpTs && request == OpType.PUT) {
      get.setMaxVersions(1);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("Scanning for cells with " + get);
    }
    // This Map is identical to familyMap. The key is a BR rather than byte[].
    // It will be easy to do gets over this new Map as we can create get keys over the Cell cf by
    // new SimpleByteRange(cell.familyArray, cell.familyOffset, cell.familyLen)
    Map<ByteRange, List<Cell>> familyMap1 = new HashMap<>();
    for (Map.Entry<byte[], ? extends Collection<?>> entry : familyMap.entrySet()) {
      if (entry.getValue() instanceof List) {
        familyMap1.put(new SimpleMutableByteRange(entry.getKey()), (List<Cell>) entry.getValue());
      }
    }
    RegionScanner scanner = getRegion(e).getScanner(new Scan(get));
    List<Cell> cells = org.apache.hbase.thirdparty.com.google.common.collect.Lists.newArrayList();
    Cell prevCell = null;
    ByteRange curFam = new SimpleMutableByteRange();
    boolean curColAllVersions = (request == OpType.DELETE);
    long curColCheckTs = opTs;
    boolean foundColumn = false;
    try {
      boolean more = false;
      ScannerContext scannerContext = ScannerContext.newBuilder().setBatchLimit(1).build();

      do {
        cells.clear();
        // scan with limit as 1 to hold down memory use on wide rows
        more = scanner.next(cells, scannerContext);
        for (Cell cell : cells) {
          if (LOG.isTraceEnabled()) {
            LOG.trace("Found cell " + cell);
          }
          boolean colChange = prevCell == null || !CellUtil.matchingColumn(prevCell, cell);
          if (colChange) foundColumn = false;
          prevCell = cell;
          if (!curColAllVersions && foundColumn) {
            continue;
          }
          if (colChange && considerCellTs) {
            curFam.set(cell.getFamilyArray(), cell.getFamilyOffset(), cell.getFamilyLength());
            List<Cell> cols = familyMap1.get(curFam);
            for (Cell col : cols) {
              // null/empty qualifier is used to denote a Family delete. The TS and delete type
              // associated with this is applicable for all columns within the family. That is
              // why the below (col.getQualifierLength() == 0) check.
              if ((col.getQualifierLength() == 0 && request == OpType.DELETE)
                  || CellUtil.matchingQualifier(cell, col)) {
                byte type = col.getTypeByte();
                if (considerCellTs) {
                  curColCheckTs = col.getTimestamp();
                }
                // For a Delete op we pass allVersions as true. When a Delete Mutation contains
                // a version delete for a column no need to check all the covering cells within
                // that column. Check all versions when Type is DeleteColumn or DeleteFamily
                // One version delete types are Delete/DeleteFamilyVersion
                curColAllVersions =
                    (KeyValue.Type.DeleteColumn.getCode() == type)
                        || (KeyValue.Type.DeleteFamily.getCode() == type);
                break;
              }
            }
          }
          if (cell.getTimestamp() > curColCheckTs) {
            // Just ignore this cell. This is not a covering cell.
            continue;
          }
          foundColumn = true;
          for (Action action : actions) {
            // Are there permissions for this user for the cell?
            if (!getAuthManager().authorizeCell(user, getTableName(e), cell, action)) {
              // We can stop if the cell ACL denies access
              return false;
            }
          }
          cellGrants++;
        }
      } while (more);
    } catch (AccessDeniedException ex) {
      throw ex;
    } catch (IOException ex) {
      LOG.error("Exception while getting cells to calculate covering permission", ex);
    } finally {
      scanner.close();
    }
    // We should not authorize unless we have found one or more cell ACLs that
    // grant access. This code is used to check for additional permissions
    // after no table or CF grants are found.
    return cellGrants > 0;
  }

  private Map<byte[], ? extends Collection<byte[]>> makeFamilyMap(byte[] family, byte[] qualifier) {
    if (family == null) {
      return null;
    }

    Map<byte[], Collection<byte[]>> familyMap = new TreeMap<>(Bytes.BYTES_COMPARATOR);
    familyMap.put(family, qualifier != null ? ImmutableSet.of(qualifier) : null);
    return familyMap;
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
    checkForReservedTagPresence(user, put);

    // Require READ and WRITE permissions on the table, CF, and KV to update
    RegionCoprocessorEnvironment env = c.getEnvironment();
    Map<byte[], ? extends Collection<byte[]>> families = makeFamilyMap(family, qualifier);
    AuthResult authResult =
        permissionGranted(OpType.CHECK_AND_PUT, user, env, families, Action.READ, Action.WRITE);
    AccessChecker.logResult(authResult);
    if (!authResult.isAllowed()) {
      if (cellFeaturesEnabled && !compatibleEarlyTermination) {
        put.setAttribute(CHECK_COVERING_PERM, TRUE);
      } else if (authorizationEnabled) {
        throw new AccessDeniedException("Insufficient permissions " + authResult.toContextString());
      }
    }

    byte[] bytes = put.getAttribute(AccessControlConstants.OP_ATTRIBUTE_ACL);
    if (bytes != null) {
      if (cellFeaturesEnabled) {
        addCellPermissions(bytes, put.getFamilyCellMap());
      } else {
        throw new DoNotRetryIOException("Cell ACLs cannot be persisted");
      }
    }
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
    if (put.getAttribute(CHECK_COVERING_PERM) != null) {
      // We had failure with table, cf and q perm checks and now giving a chance for cell
      // perm check
      TableName table = c.getEnvironment().getRegion().getRegionInfo().getTable();
      Map<byte[], ? extends Collection<byte[]>> families = makeFamilyMap(family, qualifier);
      AuthResult authResult = null;
      User user = getActiveUser(c);
      if (checkCoveringPermission(
          user,
          OpType.CHECK_AND_PUT,
          c.getEnvironment(),
          row,
          families,
          HConstants.LATEST_TIMESTAMP,
          Action.READ)) {
        authResult =
            AuthResult.allow(
                OpType.CHECK_AND_PUT.toString(),
                "Covering cell set",
                user,
                Action.READ,
                table,
                families);
      } else {
        authResult =
            AuthResult.deny(
                OpType.CHECK_AND_PUT.toString(),
                "Covering cell set",
                user,
                Action.READ,
                table,
                families);
      }
      AccessChecker.logResult(authResult);
      if (authorizationEnabled && !authResult.isAllowed()) {
        throw new AccessDeniedException("Insufficient permissions " + authResult.toContextString());
      }
    }
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
    // An ACL on a delete is useless, we shouldn't allow it
    if (delete.getAttribute(AccessControlConstants.OP_ATTRIBUTE_ACL) != null) {
      throw new DoNotRetryIOException("ACL on checkAndDelete has no effect: " + delete.toString());
    }
    // Require READ and WRITE permissions on the table, CF, and the KV covered
    // by the delete
    RegionCoprocessorEnvironment env = c.getEnvironment();
    Map<byte[], ? extends Collection<byte[]>> families = makeFamilyMap(family, qualifier);
    User user = getActiveUser(c);
    AuthResult authResult =
        permissionGranted(OpType.CHECK_AND_DELETE, user, env, families, Action.READ, Action.WRITE);
    AccessChecker.logResult(authResult);
    if (!authResult.isAllowed()) {
      if (cellFeaturesEnabled && !compatibleEarlyTermination) {
        delete.setAttribute(CHECK_COVERING_PERM, TRUE);
      } else if (authorizationEnabled) {
        throw new AccessDeniedException("Insufficient permissions " + authResult.toContextString());
      }
    }
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
    if (delete.getAttribute(CHECK_COVERING_PERM) != null) {
      // We had failure with table, cf and q perm checks and now giving a chance for cell
      // perm check
      TableName table = c.getEnvironment().getRegion().getRegionInfo().getTable();
      Map<byte[], ? extends Collection<byte[]>> families = makeFamilyMap(family, qualifier);
      AuthResult authResult = null;
      User user = getActiveUser(c);
      if (checkCoveringPermission(
          user,
          OpType.CHECK_AND_DELETE,
          c.getEnvironment(),
          row,
          families,
          HConstants.LATEST_TIMESTAMP,
          Action.READ)) {
        authResult =
            AuthResult.allow(
                OpType.CHECK_AND_DELETE.toString(),
                "Covering cell set",
                user,
                Action.READ,
                table,
                families);
      } else {
        authResult =
            AuthResult.deny(
                OpType.CHECK_AND_DELETE.toString(),
                "Covering cell set",
                user,
                Action.READ,
                table,
                families);
      }
      AccessChecker.logResult(authResult);
      if (authorizationEnabled && !authResult.isAllowed()) {
        throw new AccessDeniedException("Insufficient permissions " + authResult.toContextString());
      }
    }
    return result;
  }

  @Override
  public Result preAppend(ObserverContext<RegionCoprocessorEnvironment> c, Append append)
      throws IOException {
    User user = getActiveUser(c);
    checkForReservedTagPresence(user, append);

    // Require WRITE permission to the table, CF, and the KV to be appended
    RegionCoprocessorEnvironment env = c.getEnvironment();
    Map<byte[], ? extends Collection<Cell>> families = append.getFamilyCellMap();
    AuthResult authResult = permissionGranted(OpType.APPEND, user, env, families, Action.WRITE);
    AccessChecker.logResult(authResult);
    if (!authResult.isAllowed()) {
      if (cellFeaturesEnabled && !compatibleEarlyTermination) {
        append.setAttribute(CHECK_COVERING_PERM, TRUE);
      } else if (authorizationEnabled) {
        throw new AccessDeniedException("Insufficient permissions " + authResult.toContextString());
      }
    }

    byte[] bytes = append.getAttribute(AccessControlConstants.OP_ATTRIBUTE_ACL);
    if (bytes != null) {
      if (cellFeaturesEnabled) {
        addCellPermissions(bytes, append.getFamilyCellMap());
      } else {
        throw new DoNotRetryIOException("Cell ACLs cannot be persisted");
      }
    }

    return null;
  }

  @Override
  public Result preIncrement(
      final ObserverContext<RegionCoprocessorEnvironment> c, final Increment increment)
      throws IOException {
    User user = getActiveUser(c);
    checkForReservedTagPresence(user, increment);

    // Require WRITE permission to the table, CF, and the KV to be replaced by
    // the incremented value
    RegionCoprocessorEnvironment env = c.getEnvironment();
    Map<byte[], ? extends Collection<Cell>> families = increment.getFamilyCellMap();
    AuthResult authResult = permissionGranted(OpType.INCREMENT, user, env, families, Action.WRITE);
    AccessChecker.logResult(authResult);
    if (!authResult.isAllowed()) {
      if (cellFeaturesEnabled && !compatibleEarlyTermination) {
        increment.setAttribute(CHECK_COVERING_PERM, TRUE);
      } else if (authorizationEnabled) {
        throw new AccessDeniedException("Insufficient permissions " + authResult.toContextString());
      }
    }

    byte[] bytes = increment.getAttribute(AccessControlConstants.OP_ATTRIBUTE_ACL);
    if (bytes != null) {
      if (cellFeaturesEnabled) {
        addCellPermissions(bytes, increment.getFamilyCellMap());
      } else {
        throw new DoNotRetryIOException("Cell ACLs cannot be persisted");
      }
    }

    return null;
  }

  @Override
  public RegionScanner postScannerOpen(
      final ObserverContext<RegionCoprocessorEnvironment> c, final Scan scan, final RegionScanner s)
      throws IOException {
    User user = getActiveUser(c);
    if (user != null && user.getShortName() != null) {
      // store reference to scanner owner for later checks
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
    requireScannerOwner(s);
    return hasNext;
  }

  @Override
  public void preScannerClose(
      final ObserverContext<RegionCoprocessorEnvironment> c, final InternalScanner s)
      throws IOException {
    requireScannerOwner(s);
  }

  @Override
  public void postScannerClose(
      final ObserverContext<RegionCoprocessorEnvironment> c, final InternalScanner s)
      throws IOException {
    // clean up any associated owner mapping
    scannerOwners.remove(s);
  }

  /**
   * Verify, when servicing an RPC, that the caller is the scanner owner. If so, we assume that
   * access control is correctly enforced based on the checks performed in preScannerOpen()
   */
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
  public void preBulkLoadHFile(
      ObserverContext<RegionCoprocessorEnvironment> ctx, List<Pair<byte[], String>> familyPaths)
      throws IOException {
    User user = getActiveUser(ctx);
    for (Pair<byte[], String> el : familyPaths) {
      accessChecker.requirePermission(
          user,
          "preBulkLoadHFile",
          ctx.getEnvironment().getRegion().getTableDescriptor().getTableName(),
          el.getFirst(),
          null,
          null,
          Action.ADMIN,
          Action.CREATE);
    }
  }

  @Override
  public void preExecuteProcedures(ObserverContext<RegionServerCoprocessorEnvironment> ctx)
      throws IOException {
    checkSystemOrSuperUser(getActiveUser(ctx));
  }

  // TODO replace with user that returns thw whole name for getShortName()
  private User getActiveUser(ObserverContext<?> ctx) throws IOException {
    // for non-rpc handling, fallback to system user
    Optional<User> optionalUser = ctx.getCaller();
    if (optionalUser.isPresent()) {
      return optionalUser.get();
    }
    return userProvider.getCurrent();
  }

  //  @Override
  //  public void preGrant(ObserverContext<MasterCoprocessorEnvironment> ctx,
  //    UserPermission userPermission, boolean mergeExistingPermissions) throws IOException {
  //    preGrantOrRevoke(getActiveUser(ctx), "grant", userPermission);
  //  }
  //
  //  @Override
  //  public void preRevoke(ObserverContext<MasterCoprocessorEnvironment> ctx,
  //    UserPermission userPermission) throws IOException {
  //    preGrantOrRevoke(getActiveUser(ctx), "revoke", userPermission);
  //  }
  //
  //  private void preGrantOrRevoke(User caller, String request, UserPermission userPermission)
  //          throws IOException {
  //    switch (userPermission.getPermission().getAccessScope()) {
  //      case GLOBAL:
  //        accessChecker.requireGlobalPermission(caller, request, Action.ADMIN, "");
  //        break;
  //      case NAMESPACE:
  //        NamespacePermission namespacePerm = (NamespacePermission)
  // userPermission.getPermission();
  //        accessChecker.requireNamespacePermission(caller, request, namespacePerm.getNamespace(),
  //                null, Action.ADMIN);
  //        break;
  //      case TABLE:
  //        TablePermission tablePerm = (TablePermission) userPermission.getPermission();
  //        accessChecker.requirePermission(caller, request, tablePerm.getTableName(),
  //                tablePerm.getFamily(), tablePerm.getQualifier(), null, Action.ADMIN);
  //        break;
  //      default:
  //    }
  //    if (!Superusers.isSuperUser(caller)) {
  //      accessChecker.performOnSuperuser(request, caller, userPermission.getUser());
  //    }
  //  }

  @Override
  public void preGetUserPermissions(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      String userName,
      String namespace,
      TableName tableName,
      byte[] family,
      byte[] qualifier)
      throws IOException {
    preGetUserPermissions(getActiveUser(ctx), userName, namespace, tableName, family, qualifier);
  }

  private void preGetUserPermissions(
      User caller,
      String userName,
      String namespace,
      TableName tableName,
      byte[] family,
      byte[] qualifier)
      throws IOException {
    if (tableName != null) {
      accessChecker.requirePermission(
          caller, "getUserPermissions", tableName, family, qualifier, userName, Action.ADMIN);
    } else if (namespace != null) {
      accessChecker.requireNamespacePermission(
          caller, "getUserPermissions", namespace, userName, Action.ADMIN);
    } else {
      accessChecker.requirePermission(caller, "getUserPermissions", userName, Action.ADMIN);
    }
  }

  @Override
  public void preHasUserPermissions(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      String userName,
      List<Permission> permissions)
      throws IOException {
    preHasUserPermissions(getActiveUser(ctx), userName, permissions);
  }

  private void preHasUserPermissions(User caller, String userName, List<Permission> permissions)
      throws IOException {
    String request = "hasUserPermissions";
    for (Permission permission : permissions) {
      if (!caller.getShortName().equals(userName)) {
        // User should have admin privilege if checking permission for other users
        if (permission instanceof TablePermission) {
          TablePermission tPerm = (TablePermission) permission;
          accessChecker.requirePermission(
              caller,
              request,
              tPerm.getTableName(),
              tPerm.getFamily(),
              tPerm.getQualifier(),
              userName,
              Action.ADMIN);
        } else if (permission instanceof NamespacePermission) {
          NamespacePermission nsPerm = (NamespacePermission) permission;
          accessChecker.requireNamespacePermission(
              caller, request, nsPerm.getNamespace(), userName, Action.ADMIN);
        } else {
          accessChecker.requirePermission(caller, request, userName, Action.ADMIN);
        }
      } else {
        // User don't need ADMIN privilege for self check.
        // Setting action as null in AuthResult to display empty action in audit log
        AuthResult result;
        if (permission instanceof TablePermission) {
          TablePermission tPerm = (TablePermission) permission;
          result =
              AuthResult.allow(
                  request,
                  "Self user validation allowed",
                  caller,
                  null,
                  tPerm.getTableName(),
                  tPerm.getFamily(),
                  tPerm.getQualifier());
        } else if (permission instanceof NamespacePermission) {
          NamespacePermission nsPerm = (NamespacePermission) permission;
          result =
              AuthResult.allow(
                  request, "Self user validation allowed", caller, null, nsPerm.getNamespace());
        } else {
          result =
              AuthResult.allow(
                  request, "Self user validation allowed", caller, null, null, null, null);
        }
        AccessChecker.logResult(result);
      }
    }
  }

  @Override
  public void preClearRegionBlockCache(ObserverContext<RegionServerCoprocessorEnvironment> ctx)
      throws IOException {
    accessChecker.requirePermission(
        getActiveUser(ctx), "clearRegionBlockCache", null, Permission.Action.ADMIN);
  }

  @Override
  public void preUpdateRegionServerConfiguration(
      ObserverContext<RegionServerCoprocessorEnvironment> ctx, Configuration preReloadConf)
      throws IOException {
    accessChecker.requirePermission(
        getActiveUser(ctx), "updateConfiguration", null, Permission.Action.ADMIN);
  }

  @Override
  public void preUpdateMasterConfiguration(
      ObserverContext<MasterCoprocessorEnvironment> ctx, Configuration preReloadConf)
      throws IOException {
    accessChecker.requirePermission(
        getActiveUser(ctx), "updateConfiguration", null, Permission.Action.ADMIN);
  }
}
