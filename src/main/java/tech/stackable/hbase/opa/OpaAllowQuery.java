package tech.stackable.hbase.opa;

import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.security.access.Permission;
import org.apache.hadoop.security.UserGroupInformation;

public class OpaAllowQuery {
  public final OpaAllowQueryInput input;

  public OpaAllowQuery(OpaAllowQueryInput input) {
    this.input = input;
  }

  public static class OpaAllowQueryInput {
    public OpaQueryUgi callerUgi;
    public TableName table;
    public Permission.Action action;

    public OpaAllowQueryInput(UserGroupInformation ugi, TableName table, Permission.Action action) {
      this.callerUgi = new OpaQueryUgi(ugi);

      this.table = table;
      this.action = action;
    }
  }
}
