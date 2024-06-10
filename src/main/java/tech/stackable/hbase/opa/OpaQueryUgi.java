package tech.stackable.hbase.opa;

import java.util.List;
import org.apache.hadoop.security.UserGroupInformation;

public class OpaQueryUgi {
  // Wrapping this
  public final OpaQueryUgi realUser;
  public final String userName;
  public final String shortUserName;

  public String primaryGroup;
  public final List<String> groups;

  public final UserGroupInformation.AuthenticationMethod authenticationMethod;
  public final UserGroupInformation.AuthenticationMethod realAuthenticationMethod;

  /**
   * Wrapper around {@link UserGroupInformation}, which does not throw random errors during
   * serialization when no primary group is known for the user. "Caused by:
   * com.fasterxml.jackson.databind.JsonMappingException: Unexpected IOException (of type
   * java.io.IOException): There is no primary group for UGI
   * hive/hive-iceberg.default.svc.cluster.local@KNAB.COM (auth:KERBEROS)"
   */
  public OpaQueryUgi(UserGroupInformation ugi) {
    UserGroupInformation realUser = ugi.getRealUser();
    if (realUser != null) {
      this.realUser = new OpaQueryUgi(ugi.getRealUser());
    } else {
      this.realUser = null;
    }
    this.userName = ugi.getUserName();
    this.shortUserName = ugi.getShortUserName();

    // groups will be managed in opa rego rules so do not attempt to have
    // this set by e.g. ugi.getPrimaryGroupName() -> ShellBasedUnixGroupsMapping
    this.primaryGroup = null;

    this.groups = ugi.getGroups();
    this.authenticationMethod = ugi.getAuthenticationMethod();
    this.realAuthenticationMethod = ugi.getRealAuthenticationMethod();
  }
}
