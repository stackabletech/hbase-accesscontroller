package tech.stackable.hbase;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.apache.hadoop.hbase.security.access.SecureTestUtil.createTable;
import static org.apache.hadoop.hbase.security.access.SecureTestUtil.deleteTable;
import static org.junit.Assert.fail;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import java.util.ArrayList;
import java.util.List;
import org.apache.hadoop.hbase.HColumnDescriptor;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.client.*;
import org.apache.hadoop.hbase.coprocessor.ObserverContextImpl;
import org.apache.hadoop.hbase.master.MasterCoprocessorHost;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.access.SecureTestUtil;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.security.AccessControlException;
import org.junit.Rule;
import org.junit.Test;

public class TestOpenPolicyAgentAccessController extends TestUtils {
  public static final String OPA_URL = "http://localhost:8089";

  @Rule public WireMockRule wireMockRule = new WireMockRule(8089);

  @Test
  public void testCreateAndPut() throws Exception {
    LOG.info("testCreateAndPut - start");

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
    LOG.info("testCreateAndPut - complete");
  }

  @Test
  public void testDeniedCreate() throws Exception {
    LOG.info("testDeniedCreate - start");

    // let all set-up calls succeed
    stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));
    setup(OpenPolicyAgentAccessController.class, false, OPA_URL);

    try {
      // re-stub so that any subsequent calls will fail
      stubFor(post("/").willReturn(ok().withBody("{\"result\": \"false\"}")));
      HTableDescriptor htd = getHTableDescriptor();
      createTable(TEST_UTIL, TEST_UTIL.getAdmin(), htd, new byte[][] {Bytes.toBytes("s")});
      fail("AccessControlException should have been thrown");
    } catch (AccessControlException e) {
      LOG.info("AccessControlException as expected: [{}]", e.getMessage());
    }

    tearDown();
    LOG.info("testDeniedCreate - complete");
  }

  @Test
  public void testDeniedCreateByUser() throws Exception {
    stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));
    setup(OpenPolicyAgentAccessController.class, false, OPA_URL);

    User userDenied = User.createUserForTesting(conf, "cannotCreateTables", new String[0]);

    SecureTestUtil.AccessTestAction createTable =
        () -> {
          HTableDescriptor htd = getHTableDescriptor();
          getOpaController()
              .preCreateTable(ObserverContextImpl.createAndPrepare(CP_ENV), htd, null);
          return null;
        };

    // re-stub so that the call fails for the given user
    stubFor(
        post("/")
            .withRequestBody(
                matchingJsonPath("$.input.callerUgi[?(@.userName == 'cannotCreateTables')]"))
            .willReturn(ok().withBody("{\"result\": \"false\"}")));

    try {
      userDenied.runAs(createTable);
      fail("AccessControlException should have been thrown");
    } catch (AccessControlException e) {
      LOG.info("AccessControlException as expected: [{}]", e.getMessage());
    }

    tearDown();
  }

  private static HTableDescriptor getHTableDescriptor() {
    HTableDescriptor htd = new HTableDescriptor(TEST_TABLE);
    HColumnDescriptor hcd = new HColumnDescriptor(TEST_FAMILY);
    hcd.setMaxVersions(100);
    htd.addFamily(hcd);
    htd.setOwner(USER_OWNER);

    return htd;
  }

  private OpenPolicyAgentAccessController getOpaController() {
    MasterCoprocessorHost masterCpHost =
        TEST_UTIL.getMiniHBaseCluster().getMaster().getMasterCoprocessorHost();
    return masterCpHost.findCoprocessor(OpenPolicyAgentAccessController.class);
  }
}
