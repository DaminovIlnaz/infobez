package ru.itis.diffiehellman.csi.tests;

import org.junit.*;
import ru.itis.diffiehellman.csi.DH;
import ru.itis.diffiehellman.util.Strings;

import javax.crypto.KeyAgreement;

import static org.junit.Assert.fail;

public class DHTest {

    public DHTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    @Test
    public void agreeOnKeysDefaultValuePG() {
        try {
            System.out.println("agreeOnKeysDefaultValuePG");
            DH alice = new DH(DH.USE_DEF_DH_PARAMS);
            assert(agreeOnKeys(alice));
        } catch (Exception ex) {
            fail("An Exception Occurred");
            ex.printStackTrace();
        }
    }
    
    @Test
    public void agreeOnKeysGeneratedPG() {
        try {
            System.out.println("agreeOnKeysGeneratedPG");
            DH alice = new DH(DH.GENERATE_DH_PARAMS);
            assert(agreeOnKeys(alice));
        } catch (Exception ex) {
            fail("An Exception Occurred");
            ex.printStackTrace();
        }
    }

    private boolean agreeOnKeys(DH alice) throws Exception {
        DH bob = new DH(alice.getDHPublicKey().getParams());

        KeyAgreement kab = bob.getDHKeyAgreement();
        KeyAgreement kaa = alice.getDHKeyAgreement();

        kaa.doPhase(bob.getDHPublicKey(), true);
        kab.doPhase(alice.getDHPublicKey(), true);

        return Strings.toHexString(kab.generateSecret()).equals(
                Strings.toHexString(kaa.generateSecret()));
    }
}
