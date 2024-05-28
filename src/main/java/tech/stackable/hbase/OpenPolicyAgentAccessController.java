package tech.stackable.hbase;

import com.google.protobuf.RpcCallback;
import com.google.protobuf.RpcController;
import java.io.IOException;
import java.util.*;
import org.apache.hadoop.hbase.*;
import org.apache.hadoop.hbase.client.*;
import org.apache.hadoop.hbase.coprocessor.*;
import org.apache.hadoop.hbase.protobuf.generated.AccessControlProtos;
import org.apache.hadoop.hbase.regionserver.*;
import org.apache.hadoop.hbase.security.AccessDeniedException;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.UserProvider;
import org.apache.hadoop.hbase.security.access.*;
import org.apache.hadoop.hbase.wal.WALEdit;
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

  @Override
  public void grant(
      RpcController rpcController,
      AccessControlProtos.GrantRequest grantRequest,
      RpcCallback<AccessControlProtos.GrantResponse> rpcCallback) {
    LOG.info("Call...");
  }

  @Override
  public void revoke(
      RpcController rpcController,
      AccessControlProtos.RevokeRequest revokeRequest,
      RpcCallback<AccessControlProtos.RevokeResponse> rpcCallback) {
    LOG.info("Call...");
  }

  @Override
  public void getUserPermissions(
      RpcController rpcController,
      AccessControlProtos.GetUserPermissionsRequest getUserPermissionsRequest,
      RpcCallback<AccessControlProtos.GetUserPermissionsResponse> rpcCallback) {
    LOG.info("Call...");
  }

  @Override
  public void checkPermissions(
      RpcController rpcController,
      AccessControlProtos.CheckPermissionsRequest checkPermissionsRequest,
      RpcCallback<AccessControlProtos.CheckPermissionsResponse> rpcCallback) {
    LOG.info("Call...");
  }

  @Override
  public void hasPermission(
      RpcController rpcController,
      AccessControlProtos.HasPermissionRequest hasPermissionRequest,
      RpcCallback<AccessControlProtos.HasPermissionResponse> rpcCallback) {
    LOG.info("Call...");
  }

  @Override
  public void prePut(
      ObserverContext<RegionCoprocessorEnvironment> c, Put put, WALEdit edit, Durability durability)
      throws IOException {
    LOG.info("prePut1...");
    throw new AccessDeniedException("Insufficient permissions!");
  }

  @Override
  public void prePut(ObserverContext<RegionCoprocessorEnvironment> c, Put put, WALEdit edit)
      throws IOException {
    LOG.info("prePut2...");
    throw new AccessDeniedException("Insufficient permissions!");
  }

  @Override
  public void preCreateTable(
      ObserverContext<MasterCoprocessorEnvironment> c, TableDescriptor desc, RegionInfo[] regions)
      throws IOException {
    LOG.info("preCreateTable...");
  }

  @Override
  public void postCompletedCreateTableAction(
      final ObserverContext<MasterCoprocessorEnvironment> c,
      final TableDescriptor desc,
      final RegionInfo[] regions)
      throws IOException {
    LOG.info("postCompletedCreateTableAction...");
  }
}
