package tech.stackable.hbase;

import com.google.protobuf.RpcCallback;
import com.google.protobuf.RpcController;
import org.apache.hadoop.hbase.HBaseInterfaceAudience;
import org.apache.hadoop.hbase.NamespaceDescriptor;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.RegionInfo;
import org.apache.hadoop.hbase.client.TableDescriptor;
import org.apache.hadoop.hbase.coprocessor.*;
import org.apache.hadoop.hbase.protobuf.generated.AccessControlProtos;
import org.apache.hadoop.hbase.security.access.Permission;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.yetus.audience.InterfaceAudience;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

@CoreCoprocessor
@InterfaceAudience.LimitedPrivate(HBaseInterfaceAudience.CONFIG)
public class AllowAccessController implements MasterCoprocessor, RegionCoprocessor,
        RegionServerCoprocessor, AccessControlProtos.AccessControlService.Interface, MasterObserver, RegionObserver,
        RegionServerObserver, EndpointObserver, BulkLoadObserver {

    private static final Logger LOG = LoggerFactory.getLogger(AllowAccessController.class);

    /******************************** AccessControlService.Interface implementations ********************************/
    // Methods of the AccessControlService.Interface have no default implementation.
    // Granting, revoking and retrieving user permissions is not supported here.

    @Override
    public void grant(RpcController controller, AccessControlProtos.GrantRequest request, RpcCallback<AccessControlProtos.GrantResponse> done) {
        LOG.error("Granting permissions is a NO-OP for the AllowAccessController");
    }

    @Override
    public void revoke(RpcController controller, AccessControlProtos.RevokeRequest request, RpcCallback<AccessControlProtos.RevokeResponse> done) {
        LOG.error("Revoking permissions is a NO-OP for the AllowAccessController");
    }

    @Override
    public void getUserPermissions(RpcController controller, AccessControlProtos.GetUserPermissionsRequest request, RpcCallback<AccessControlProtos.GetUserPermissionsResponse> done) {
        LOG.error("Retrieving user permissions is a NO-OP for the AllowAccessController");
    }

    @Override
    public void checkPermissions(RpcController controller, AccessControlProtos.CheckPermissionsRequest request, RpcCallback<AccessControlProtos.CheckPermissionsResponse> done) {
        LOG.info("Checking permissions");
    }

    @Override
    public void hasPermission(RpcController controller, AccessControlProtos.HasPermissionRequest request, RpcCallback<AccessControlProtos.HasPermissionResponse> done) {
        LOG.info("Checking if permission is granted");
    }


    /*********************************** Observer implementations ***********************************/

    @Override
    public void preCreateTable(ObserverContext<MasterCoprocessorEnvironment> c, TableDescriptor desc,
                               RegionInfo[] regions) throws IOException {
        Set<byte[]> families = desc.getColumnFamilyNames();
        Map<byte[], Set<byte[]>> familyMap = new TreeMap<>(Bytes.BYTES_COMPARATOR);
        for (byte[] family : families) {
            familyMap.put(family, null);
        }
        requireNamespacePermission(c, "createTable", desc.getTableName().getNamespaceAsString(),
                desc.getTableName(), familyMap, Permission.Action.ADMIN, Permission.Action.CREATE);
    }

    @Override
    public void preDeleteTable(ObserverContext<MasterCoprocessorEnvironment> c, TableName tableName)
            throws IOException {
        requirePermission(c, "deleteTable", tableName, null, null, Permission.Action.ADMIN, Permission.Action.CREATE);
    }

    @Override
    public void preCreateNamespace(ObserverContext<MasterCoprocessorEnvironment> ctx,
                                   NamespaceDescriptor ns) throws IOException {
        requireGlobalPermission(ctx, "createNamespace", Permission.Action.ADMIN, ns.getName());
    }

    @Override
    public void preDeleteNamespace(ObserverContext<MasterCoprocessorEnvironment> ctx,
                                   String namespace) throws IOException {
        requireGlobalPermission(ctx, "deleteNamespace", Permission.Action.ADMIN, namespace);
    }

    /*********************************** Private ***********************************/
    // These should probably be implemented in a policy backend that interacts with OPA.

    private void requireNamespacePermission(ObserverContext<?> ctx, String request, String namespace,
                                           TableName tableName, Map<byte[], ? extends Collection<byte[]>> familyMap, Permission.Action... permissions)
            throws IOException {
        //accessChecker.requireNamespacePermission(getActiveUser(ctx), request, namespace, tableName, familyMap, permissions);
        LOG.info("requireNamespacePermission namespace={}, tableName={}, familyMap={}, permissions={}", namespace, tableName, familyMap, permissions);
    }

    private void requirePermission(ObserverContext<?> ctx, String request, TableName tableName,
                                  byte[] family, byte[] qualifier, Permission.Action... permissions) throws IOException {

        //accessChecker.requirePermission(getActiveUser(ctx), request, tableName, family, qualifier, null, permissions);
        LOG.info("requirePermission tableName={}, family={}, qualifier={}, permissions={}", tableName, family, qualifier, permissions);
    }

    private void requireGlobalPermission(ObserverContext<?> ctx, String request, Permission.Action perm,
                                        String namespace) throws IOException {
        //accessChecker.requireGlobalPermission(getActiveUser(ctx), request, perm, namespace);
        LOG.info("requireGlobalPermission namespace={}, perm={}", namespace, perm);
    }

}
