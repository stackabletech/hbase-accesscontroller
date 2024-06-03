package tech.stackable.hbase;

import com.google.protobuf.RpcCallback;
import com.google.protobuf.RpcController;
import org.apache.hadoop.hbase.HBaseInterfaceAudience;
import org.apache.hadoop.hbase.coprocessor.*;
import org.apache.hadoop.hbase.protobuf.generated.AccessControlProtos;
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

  @Override
  public void grant(
      RpcController controller,
      AccessControlProtos.GrantRequest request,
      RpcCallback<AccessControlProtos.GrantResponse> done) {
    LOG.info("xxx Granting permission");
  }

  @Override
  public void revoke(
      RpcController controller,
      AccessControlProtos.RevokeRequest request,
      RpcCallback<AccessControlProtos.RevokeResponse> done) {
    LOG.info("xxx Revoking permission");
  }

  @Override
  public void getUserPermissions(
      RpcController controller,
      AccessControlProtos.GetUserPermissionsRequest request,
      RpcCallback<AccessControlProtos.GetUserPermissionsResponse> done) {
    LOG.info("xxx Getting user permissions");
  }

  @Override
  public void checkPermissions(
      RpcController controller,
      AccessControlProtos.CheckPermissionsRequest request,
      RpcCallback<AccessControlProtos.CheckPermissionsResponse> done) {
    LOG.info("xxx Checking permissions");
  }

  @Override
  public void hasPermission(
      RpcController controller,
      AccessControlProtos.HasPermissionRequest request,
      RpcCallback<AccessControlProtos.HasPermissionResponse> done) {
    LOG.info("xxx Checking if permission is granted");
  }
}
