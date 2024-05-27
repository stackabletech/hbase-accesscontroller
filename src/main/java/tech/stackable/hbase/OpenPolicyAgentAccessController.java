package tech.stackable.hbase;

import com.google.protobuf.RpcCallback;
import com.google.protobuf.RpcController;
import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import org.apache.hadoop.hbase.CompoundConfiguration;
import org.apache.hadoop.hbase.CoprocessorEnvironment;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.RegionInfo;
import org.apache.hadoop.hbase.coprocessor.*;
import org.apache.hadoop.hbase.protobuf.generated.AccessControlProtos;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.UserProvider;
import org.apache.hadoop.hbase.security.access.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
  private RegionCoprocessorEnvironment regionEnv;

  private UserProvider userProvider;

  @Override
  public void start(CoprocessorEnvironment env) throws IOException {
    LOG.info("Starting OpenPolicyAgentAccessController...");
    CompoundConfiguration conf = new CompoundConfiguration();
    conf.add(env.getConfiguration());
    this.userProvider = UserProvider.instantiate(env.getConfiguration());
  }

  /**
   * Returns the active user to which authorization checks should be applied. If we are in the
   * context of an RPC call, the remote user is used, otherwise the currently logged in user is
   * used.
   */
  private User getActiveUser(ObserverContext<?> ctx) throws IOException {
    // for non-rpc handling, fallback to system user
    LOG.info("Active user from [{}]", ctx);
    Optional<User> optionalUser = ctx.getCaller();
    if (optionalUser.isPresent()) {
      return optionalUser.get();
    }
    return userProvider.getCurrent();
  }

  public void requireAccess(
      ObserverContext<?> ctx, String request, TableName tableName, Permission.Action... permissions)
      throws IOException {
    LOG.info("requireAccess from {} for {} on {}", ctx, request, tableName);
  }

  public void requirePermission(ObserverContext<?> ctx, String request, Permission.Action perm)
      throws IOException {
    LOG.info("requirePermission from {} for {} with {}", ctx, request, perm);
  }

  public void requireGlobalPermission(
      ObserverContext<?> ctx,
      String request,
      Permission.Action perm,
      TableName tableName,
      Map<byte[], ? extends Collection<byte[]>> familyMap)
      throws IOException {
    LOG.info(
        "requireGlobalPermission from {} for {} with {}, {}, {}",
        ctx,
        request,
        perm,
        tableName,
        familyMap);
  }

  public void requireGlobalPermission(
      ObserverContext<?> ctx, String request, Permission.Action perm, String namespace)
      throws IOException {
    LOG.info("requireGlobalPermission from {} for {} with {}, {}", ctx, request, perm, namespace);
  }

  public void requireNamespacePermission(
      ObserverContext<?> ctx, String request, String namespace, Permission.Action... permissions)
      throws IOException {
    LOG.info(
        "requireNamespacePermission from {} for {} with {}, {}",
        ctx,
        request,
        namespace,
        permissions);
  }

  public void requireNamespacePermission(
      ObserverContext<?> ctx,
      String request,
      String namespace,
      TableName tableName,
      Map<byte[], ? extends Collection<byte[]>> familyMap,
      Permission.Action... permissions)
      throws IOException {
    LOG.info(
        "requireNamespacePermission from {} for {} with {}, {}, {}",
        ctx,
        request,
        namespace,
        familyMap,
        permissions);
  }

  public void requirePermission(
      ObserverContext<?> ctx,
      String request,
      TableName tableName,
      byte[] family,
      byte[] qualifier,
      Permission.Action... permissions)
      throws IOException {
    LOG.info("requirePermission from {} for {} with {}, {}", ctx, request, tableName, permissions);
  }

  public void requireTablePermission(
      ObserverContext<?> ctx,
      String request,
      TableName tableName,
      byte[] family,
      byte[] qualifier,
      Permission.Action... permissions)
      throws IOException {
    LOG.info(
        "requireTablePermission from {} for {} with {}, {}", ctx, request, tableName, permissions);
  }

  public void checkLockPermissions(
      ObserverContext<?> ctx,
      String namespace,
      TableName tableName,
      RegionInfo[] regionInfos,
      String reason)
      throws IOException {
    LOG.info(
        "checkLockPermissions from {} for {} with {}, {}, {}",
        ctx,
        namespace,
        tableName,
        regionInfos,
        reason);
  }

  @Override
  public void grant(
      RpcController rpcController,
      AccessControlProtos.GrantRequest grantRequest,
      RpcCallback<AccessControlProtos.GrantResponse> rpcCallback) {
    LOG.info("grant for {} with {}, {}", rpcController, grantRequest, rpcCallback);
  }

  @Override
  public void revoke(
      RpcController rpcController,
      AccessControlProtos.RevokeRequest revokeRequest,
      RpcCallback<AccessControlProtos.RevokeResponse> rpcCallback) {
    LOG.info("revoke for {} with {}, {}", rpcController, revokeRequest, rpcCallback);
  }

  @Override
  public void getUserPermissions(
      RpcController rpcController,
      AccessControlProtos.GetUserPermissionsRequest getUserPermissionsRequest,
      RpcCallback<AccessControlProtos.GetUserPermissionsResponse> rpcCallback) {
    LOG.info(
        "getUserPermissions for {} with {}, {}",
        rpcController,
        getUserPermissionsRequest,
        rpcCallback);
  }

  @Override
  public void checkPermissions(
      RpcController rpcController,
      AccessControlProtos.CheckPermissionsRequest checkPermissionsRequest,
      RpcCallback<AccessControlProtos.CheckPermissionsResponse> rpcCallback) {
    LOG.info(
        "checkPermissions for {} with {}, {}", rpcController, checkPermissionsRequest, rpcCallback);
  }

  @Override
  public void hasPermission(
      RpcController rpcController,
      AccessControlProtos.HasPermissionRequest hasPermissionRequest,
      RpcCallback<AccessControlProtos.HasPermissionResponse> rpcCallback) {
    LOG.info("hasPermission for {} with {}, {}", rpcController, hasPermissionRequest, rpcCallback);
  }
}
