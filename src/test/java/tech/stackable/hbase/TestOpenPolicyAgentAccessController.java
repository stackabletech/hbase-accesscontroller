package tech.stackable.hbase;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.apache.hadoop.hbase.security.access.SecureTestUtil.createTable;
import static org.apache.hadoop.hbase.security.access.SecureTestUtil.deleteTable;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import java.util.ArrayList;
import java.util.List;
import org.apache.hadoop.hbase.HColumnDescriptor;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Table;
import org.apache.hadoop.hbase.util.Bytes;
import org.junit.Rule;
import org.junit.Test;

public class TestOpenPolicyAgentAccessController extends TestUtils {
  public static final String OPA_URL = "http://localhost:8089";

  @Rule public WireMockRule wireMockRule = new WireMockRule(8089);

  @Test
  public void testPrePut() throws Exception {
    LOG.info("testPrePut - start");

    stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));

    setup(OpenPolicyAgentAccessController.class, false, OPA_URL);

    HTableDescriptor htd = getHTableDescriptor();

    createTable(TEST_UTIL, TEST_UTIL.getAdmin(), htd, new byte[][] {Bytes.toBytes("s")});

    // put some test data
    List<Put> puts = new ArrayList<>(100);
    for (int i = 0; i < 100; i++) {
      Put p = new Put(Bytes.toBytes(i));
      p.addColumn(TEST_FAMILY, Bytes.toBytes("myCol"), Bytes.toBytes("info " + i));
      puts.add(p);
    }
    Table table = TEST_UTIL.getConnection().getTable(htd.getTableName());
    table.put(puts);

    deleteTable(TEST_UTIL, TEST_TABLE);

    tearDown();
    LOG.info("testPrePut - complete");
  }

  private static HTableDescriptor getHTableDescriptor() {
    HTableDescriptor htd = new HTableDescriptor(TEST_TABLE);
    HColumnDescriptor hcd = new HColumnDescriptor(TEST_FAMILY);
    hcd.setMaxVersions(100);
    htd.addFamily(hcd);
    htd.setOwner(USER_OWNER);

    return htd;
  }
}
