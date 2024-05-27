package tech.stackable.hbase;

import com.google.protobuf.RpcCallback;
import com.google.protobuf.RpcController;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.CompoundConfiguration;
import org.apache.hadoop.hbase.CoprocessorEnvironment;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.RegionInfo;
import org.apache.hadoop.hbase.coprocessor.ObserverContext;
import org.apache.hadoop.hbase.coprocessor.RegionCoprocessorEnvironment;
import org.apache.hadoop.hbase.io.hfile.HFile;
import org.apache.hadoop.hbase.protobuf.generated.AccessControlProtos;
import org.apache.hadoop.hbase.regionserver.Region;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.UserProvider;
import org.apache.hadoop.hbase.security.access.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;

public class OpenPolicyAgentAccessController extends AccessController {

  private static final Logger LOG = LoggerFactory.getLogger(OpenPolicyAgentAccessController.class);
  private RegionCoprocessorEnvironment regionEnv;

  private UserProvider userProvider;

  @Override
  public void start(CoprocessorEnvironment env) throws IOException {
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
    Optional<User> optionalUser = ctx.getCaller();
    if (optionalUser.isPresent()) {
      return optionalUser.get();
    }
    return userProvider.getCurrent();
  }

  public void requireAccess(ObserverContext<?> ctx, String request, TableName tableName,
                            Permission.Action... permissions) throws IOException {

  }

  public void requirePermission(ObserverContext<?> ctx, String request,
                                Permission.Action perm) throws IOException {

  }

  public void requireGlobalPermission(ObserverContext<?> ctx, String request,
                                      Permission.Action perm, TableName tableName,
                                      Map<byte[], ? extends Collection<byte[]>> familyMap) throws IOException {

  }

  public void requireGlobalPermission(ObserverContext<?> ctx, String request,
                                      Permission.Action perm, String namespace) throws IOException {

  }

  public void requireNamespacePermission(ObserverContext<?> ctx, String request, String namespace,
                                         Permission.Action... permissions) throws IOException {

  }

  public void requireNamespacePermission(ObserverContext<?> ctx, String request, String namespace,
                                         TableName tableName, Map<byte[], ? extends Collection<byte[]>> familyMap,
                                         Permission.Action... permissions) throws IOException {

  }

  public void requirePermission(ObserverContext<?> ctx, String request, TableName tableName,
                                byte[] family, byte[] qualifier, Permission.Action... permissions) throws IOException {

  }

  public void requireTablePermission(ObserverContext<?> ctx, String request,
                                     TableName tableName,byte[] family, byte[] qualifier,
                                     Permission.Action... permissions) throws IOException {

  }

  public void checkLockPermissions(ObserverContext<?> ctx, String namespace,
                                   TableName tableName, RegionInfo[] regionInfos, String reason)
          throws IOException {

  }

  @Override
  public void grant(
      RpcController rpcController,
      AccessControlProtos.GrantRequest grantRequest,
      RpcCallback<AccessControlProtos.GrantResponse> rpcCallback) {}

  @Override
  public void revoke(
      RpcController rpcController,
      AccessControlProtos.RevokeRequest revokeRequest,
      RpcCallback<AccessControlProtos.RevokeResponse> rpcCallback) {}

  @Override
  public void getUserPermissions(
      RpcController rpcController,
      AccessControlProtos.GetUserPermissionsRequest getUserPermissionsRequest,
      RpcCallback<AccessControlProtos.GetUserPermissionsResponse> rpcCallback) {}

  @Override
  public void checkPermissions(
      RpcController rpcController,
      AccessControlProtos.CheckPermissionsRequest checkPermissionsRequest,
      RpcCallback<AccessControlProtos.CheckPermissionsResponse> rpcCallback) {}

  @Override
  public void hasPermission(
      RpcController rpcController,
      AccessControlProtos.HasPermissionRequest hasPermissionRequest,
      RpcCallback<AccessControlProtos.HasPermissionResponse> rpcCallback) {}
}
