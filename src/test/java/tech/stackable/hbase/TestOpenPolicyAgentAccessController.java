package tech.stackable.hbase;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.apache.hadoop.hbase.security.access.SecureTestUtil.createTable;
import static org.apache.hadoop.hbase.security.access.SecureTestUtil.deleteTable;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.apache.hadoop.hbase.HColumnDescriptor;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.util.Bytes;
import org.junit.Rule;
import org.junit.Test;

public class TestOpenPolicyAgentAccessController extends TestUtils {
  public static final String OPA_URL = "http://localhost:8089";

  @Rule public WireMockRule wireMockRule = new WireMockRule(8089);

  @Test
  public void testOpenPolicyAgentAccessControllerPrePut() throws Exception {
    LOG.info("testOpenPolicyAgentAccessController - start");

    stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));

    setup(OpenPolicyAgentAccessController.class, false, OPA_URL);

    HTableDescriptor htd = new HTableDescriptor(TEST_TABLE);
    HColumnDescriptor hcd = new HColumnDescriptor(TEST_FAMILY);
    hcd.setMaxVersions(100);
    htd.addFamily(hcd);
    htd.setOwner(USER_OWNER);

    createTable(TEST_UTIL, TEST_UTIL.getAdmin(), htd, new byte[][] {Bytes.toBytes("s")});
    deleteTable(TEST_UTIL, TEST_TABLE);

    tearDown();
    LOG.info("testOpenPolicyAgentAccessController - complete");
  }
}
