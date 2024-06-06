package tech.stackable.hbase;

import com.google.protobuf.RpcCallback;
import com.google.protobuf.RpcController;
import java.io.IOException;
import java.util.*;
import org.apache.hadoop.hbase.CoprocessorEnvironment;
import org.apache.hadoop.hbase.HBaseInterfaceAudience;
import org.apache.hadoop.hbase.NamespaceDescriptor;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.RegionInfo;
import org.apache.hadoop.hbase.client.TableDescriptor;
import org.apache.hadoop.hbase.coprocessor.*;
import org.apache.hadoop.hbase.protobuf.generated.AccessControlProtos;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.UserProvider;
import org.apache.hadoop.hbase.security.access.Permission;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.yetus.audience.InterfaceAudience;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@CoreCoprocessor
@InterfaceAudience.LimitedPrivate(HBaseInterfaceAudience.CONFIG)
public class AllowAccessController
    implements MasterCoprocessor,
        RegionCoprocessor,
        RegionServerCoprocessor,
        AccessControlProtos.AccessControlService.Interface,
        MasterObserver,
        RegionObserver,
        RegionServerObserver,
        EndpointObserver,
        BulkLoadObserver {

  private static final Logger LOG = LoggerFactory.getLogger(AllowAccessController.class);

  private UserProvider userProvider;

  /******************************** Coprocessor implementations ********************************/
  @Override
  public void start(CoprocessorEnvironment env) {
    // set the user-provider.
    this.userProvider = UserProvider.instantiate(env.getConfiguration());

    LOG.info("AllowAccessController started");
  }

  @Override
  public void stop(CoprocessorEnvironment env) {
    LOG.info("AllowAccessController stopped");
  }

  /******************************** AccessControlService.Interface implementations ********************************/
  // Methods of the AccessControlService.Interface have no default implementation.
  // Granting, revoking and retrieving user permissions is not supported here.

  @Override
  public void grant(
      RpcController controller,
      AccessControlProtos.GrantRequest request,
      RpcCallback<AccessControlProtos.GrantResponse> done) {
    LOG.error("Granting permissions is a NO-OP for the AllowAccessController");
  }

  @Override
  public void revoke(
      RpcController controller,
      AccessControlProtos.RevokeRequest request,
      RpcCallback<AccessControlProtos.RevokeResponse> done) {
    LOG.error("Revoking permissions is a NO-OP for the AllowAccessController");
  }

  @Override
  public void getUserPermissions(
      RpcController controller,
      AccessControlProtos.GetUserPermissionsRequest request,
      RpcCallback<AccessControlProtos.GetUserPermissionsResponse> done) {
    LOG.error("Retrieving user permissions is a NO-OP for the AllowAccessController");
  }

  @Override
  public void checkPermissions(
      RpcController controller,
      AccessControlProtos.CheckPermissionsRequest request,
      RpcCallback<AccessControlProtos.CheckPermissionsResponse> done) {
    LOG.info("Checking permissions");
  }

  @Override
  public void hasPermission(
      RpcController controller,
      AccessControlProtos.HasPermissionRequest request,
      RpcCallback<AccessControlProtos.HasPermissionResponse> done) {
    LOG.info("Checking if permission is granted");
  }

  /*********************************** Observer implementations ***********************************/

  @Override
  public void preCreateTable(
      ObserverContext<MasterCoprocessorEnvironment> c, TableDescriptor desc, RegionInfo[] regions)
      throws IOException {
    Set<byte[]> families = desc.getColumnFamilyNames();
    Map<byte[], Set<byte[]>> familyMap = new TreeMap<>(Bytes.BYTES_COMPARATOR);
    for (byte[] family : families) {
      familyMap.put(family, null);
    }
    requireNamespacePermission(
        c,
        "createTable",
        desc.getTableName().getNamespaceAsString(),
        desc.getTableName(),
        familyMap,
        Permission.Action.ADMIN,
        Permission.Action.CREATE);
  }

  @Override
  public void preDeleteTable(ObserverContext<MasterCoprocessorEnvironment> c, TableName tableName)
      throws IOException {
    requirePermission(
        c, "deleteTable", tableName, null, null, Permission.Action.ADMIN, Permission.Action.CREATE);
  }

  @Override
  public void preCreateNamespace(
      ObserverContext<MasterCoprocessorEnvironment> ctx, NamespaceDescriptor ns)
      throws IOException {
    requireGlobalPermission(ctx, "createNamespace", Permission.Action.ADMIN, ns.getName());
  }

  @Override
  public void preDeleteNamespace(
      ObserverContext<MasterCoprocessorEnvironment> ctx, String namespace) throws IOException {
    requireGlobalPermission(ctx, "deleteNamespace", Permission.Action.ADMIN, namespace);
  }

  /*********************************** Observer/Service Getters ***********************************/
  @Override
  public Optional<RegionObserver> getRegionObserver() {
    LOG.info("getRegionObserver");
    return Optional.of(this);
  }

  @Override
  public Optional<MasterObserver> getMasterObserver() {
    LOG.info("getMasterObserver");
    return Optional.of(this);
  }

  @Override
  public Optional<EndpointObserver> getEndpointObserver() {
    LOG.info("getEndpointObserver");
    return Optional.of(this);
  }

  @Override
  public Optional<BulkLoadObserver> getBulkLoadObserver() {
    LOG.info("getBulkLoadObserver");
    return Optional.of(this);
  }

  @Override
  public Optional<RegionServerObserver> getRegionServerObserver() {
    LOG.info("getRegionServerObserver");
    return Optional.of(this);
  }

  /*********************************** Private ***********************************/
  // These should probably be implemented in a policy backend that interacts with OPA.

  private void requireNamespacePermission(
      ObserverContext<?> ctx,
      String request,
      String namespace,
      TableName tableName,
      Map<byte[], ? extends Collection<byte[]>> familyMap,
      Permission.Action... permissions)
      throws IOException {
    var user = getActiveUser(ctx);
    LOG.info(
        "requireNamespacePermission user={}, namespace={}, tableName={}, familyMap={}, permissions={}",
        user,
        namespace,
        tableName,
        familyMap,
        permissions);
  }

  private void requirePermission(
      ObserverContext<?> ctx,
      String request,
      TableName tableName,
      byte[] family,
      byte[] qualifier,
      Permission.Action... permissions)
      throws IOException {

    // accessChecker.requirePermission(getActiveUser(ctx), request, tableName, family, qualifier,
    // null, permissions);
    LOG.info(
        "requirePermission tableName={}, family={}, qualifier={}, permissions={}",
        tableName,
        family,
        qualifier,
        permissions);
  }

  private void requireGlobalPermission(
      ObserverContext<?> ctx, String request, Permission.Action perm, String namespace)
      throws IOException {
    // accessChecker.requireGlobalPermission(getActiveUser(ctx), request, perm, namespace);
    LOG.info("requireGlobalPermission namespace={}, perm={}", namespace, perm);
  }

  private User getActiveUser(ObserverContext<?> ctx) throws IOException {
    // for non-rpc handling, fallback to system user
    Optional<User> optionalUser = ctx.getCaller();
    if (optionalUser.isPresent()) {
      return optionalUser.get();
    }
    return userProvider.getCurrent();
  }
}
