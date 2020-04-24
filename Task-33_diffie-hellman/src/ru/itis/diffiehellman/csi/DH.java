package ru.itis.diffiehellman.csi;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DH {

    private static final BigInteger P = new BigInteger(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
                    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
                    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
                    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
                    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
                    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
                    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
                    "fffffffffffff", 16);
    private static final BigInteger G = new BigInteger("2");
    public static final int USE_DEF_DH_PARAMS = 1;
    public static final int GENERATE_DH_PARAMS = 2;
    public static final String ALGORITHM = "DH";
    private DHParameterSpec dhSpec;
    private DHPublicKey publicKey;
    private KeyAgreement ka;
    private byte[] publicKeyEncoding;
    private boolean failedPublicKeyGen;

    public DH() throws Exception {
        dhSpec = new DHParameterSpec(P, G);
        init();
    }

    public DH(int mode) throws Exception {
        switch (mode) {
            case 2:
                dhSpec = generateDhParams();
                if (dhSpec == null) {
                    dhSpec = new DHParameterSpec(P, G);
                }
                break;
            default:
                dhSpec = new DHParameterSpec(P, G);
                break;
        }
        init();
    }

    public DH(DHParameterSpec dhSpec) throws Exception {
        this.dhSpec = dhSpec;
        init();
    }

    private void init() throws Exception {
        failedPublicKeyGen = false;
        generatePublicKeyEncoding();
        generatePublicKey();
    }

    public DHPublicKey getDHPublicKey() {
        return publicKey;
    }

    public KeyAgreement getDHKeyAgreement(){
        return ka;
    }

    private DHParameterSpec generateDhParams() {
        DHParameterSpec spec = null;
        try {
            AlgorithmParameterGenerator algGen =
                    AlgorithmParameterGenerator.getInstance("DH");
            algGen.init(512);
            AlgorithmParameters params = algGen.generateParameters();
            spec = (DHParameterSpec) params
                    .getParameterSpec(DHParameterSpec.class);
        } catch (Exception ex) {
            Logger.getLogger(DH.class.getName()).log(Level.WARNING, null, ex);
        } finally {
            return spec;
        }
    }

    private void generatePublicKey() throws Exception {
        if (publicKeyEncoding == null) {
            generatePublicKeyEncoding();
        }

        publicKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
            X509EncodedKeySpec x509KeySpec =
                    new X509EncodedKeySpec(publicKeyEncoding);
            publicKey =
                    (DHPublicKey)kf.generatePublic(x509KeySpec);
        } catch (Exception ex) {
            Logger.getLogger(DH.class.getName()).log(Level.SEVERE, null, ex);
            if (!failedPublicKeyGen) {
                failedPublicKeyGen = true;
                generatePublicKey();
            } else {
                throw ex;
            }
        }
    }

    private void generatePublicKeyEncoding() {
        publicKeyEncoding = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);

            keyGen.initialize(dhSpec);
            KeyPair kp = keyGen.generateKeyPair();

            ka = KeyAgreement.getInstance(ALGORITHM);
            ka.init(kp.getPrivate());

            publicKeyEncoding = kp.getPublic().getEncoded();
        } catch (Exception ex) {
            Logger.getLogger(DH.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
