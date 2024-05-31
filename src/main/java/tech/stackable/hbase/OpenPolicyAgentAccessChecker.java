package tech.stackable.hbase;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.AuthUtil;
import org.apache.hadoop.hbase.NamespaceDescriptor;
import org.apache.hadoop.hbase.security.AccessDeniedException;
import org.apache.hadoop.hbase.security.Superusers;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.access.AccessChecker;
import org.apache.hadoop.hbase.security.access.AuthResult;
import org.apache.hadoop.hbase.security.access.Permission;
import org.apache.hadoop.hbase.security.access.TablePermission;

public class OpenPolicyAgentAccessChecker extends AccessChecker {

  /**
   * Constructor with existing configuration
   *
   * @param conf Existing configuration to use
   */
  public OpenPolicyAgentAccessChecker(Configuration conf) {
    super(conf);
  }

  @Override
  public void performOnSuperuser(String request, User caller, String userToBeChecked)
      throws IOException {
    List<String> userGroups = new ArrayList<>();
    userGroups.add(userToBeChecked);
    if (!AuthUtil.isGroupPrincipal(userToBeChecked)) {
      for (String group : getOpaUserGroups(userToBeChecked)) {
        userGroups.add(AuthUtil.toGroupEntry(group));
      }
    }
    for (String name : userGroups) {
      if (Superusers.isSuperUser(name)) {
        AuthResult result =
            AuthResult.deny(
                request,
                "Granting or revoking superusers's or supergroups's permissions is not allowed",
                caller,
                Permission.Action.ADMIN,
                NamespaceDescriptor.SYSTEM_NAMESPACE_NAME_STR);
        logResult(result);
        throw new AccessDeniedException(result.getReason());
      }
    }
  }

  // TODO: implement opa calls and shortUser as being fully-qualified name
  // this could have been overridden if the method was not static.
  public static List<String> getOpaUserGroups(String user) {
    return List.of();
  }

  @Override
  public User validateCallerWithFilterUser(User caller, TablePermission tPerm, String inputUserName)
      throws IOException {
    User filterUser = null;
    if (!caller.getShortName().equals(inputUserName)) {
      // User should have admin privilege if checking permission for other users
      requirePermission(
          caller,
          "hasPermission",
          tPerm.getTableName(),
          tPerm.getFamily(),
          tPerm.getQualifier(),
          inputUserName,
          Permission.Action.ADMIN);
      // Initialize user instance for the input user name
      List<String> groups = getOpaUserGroups(inputUserName);
      filterUser = new InputUser(inputUserName, groups.toArray(new String[groups.size()]));
    } else {
      // User don't need ADMIN privilege for self check.
      // Setting action as null in AuthResult to display empty action in audit log
      AuthResult result =
          AuthResult.allow(
              "hasPermission",
              "Self user validation allowed",
              caller,
              null,
              tPerm.getTableName(),
              tPerm.getFamily(),
              tPerm.getQualifier());
      logResult(result);
      filterUser = caller;
    }
    return filterUser;
  }
}
