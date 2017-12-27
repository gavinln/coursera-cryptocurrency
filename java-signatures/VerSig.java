// From the Java tutorial: Generating & Verifying signatures
// https://docs.oracle.com/javase/tutorial/security/apisign/index.html

import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.InvalidKeyException;
import java.security.SignatureException;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.BufferedInputStream;

class VerSig {
    public PublicKey readPublicKey(String filename) {
        try {
            FileInputStream keyfis = new FileInputStream(filename);
            byte[] encKey = new byte[keyfis.available()];
            keyfis.read(encKey);
            keyfis.close();

            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
            return keyFactory.generatePublic(pubKeySpec);

        } catch(IOException e) {
            e.printStackTrace();
        } catch(NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch(NoSuchProviderException e) {
            e.printStackTrace();
        } catch(InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] readSignature(String filename) {
        try {
            FileInputStream sigfis = new FileInputStream(filename);
            byte[] sigToVerify = new byte[sigfis.available()];
            sigfis.read(sigToVerify);
            sigfis.close();
            return sigToVerify;

        } catch(IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public Signature getVerifySignature(PublicKey pubKey) {
        Signature dsa = null;
        try {
            dsa = Signature.getInstance("SHA1withDSA", "SUN");
            dsa.initVerify(pubKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return dsa;
    }

    public Signature getFileSignature(Signature sig, String filename) {
        try {
            FileInputStream datafis = new FileInputStream(filename);
            BufferedInputStream bufin = new BufferedInputStream(datafis);

            byte[] buffer = new byte[1024];
            int len;
            while (bufin.available() != 0) {
                len = bufin.read(buffer);
                sig.update(buffer, 0, len);
            };
            bufin.close();
            return sig;
        } catch(IOException e) {
            e.printStackTrace();
        } catch(SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        /* Verify a DSA signature */
        if (args.length != 3) {
            System.out.println("Usage: VerSig " +
                "publickeyfile signaturefile " + "datafile");
        }
        else try {
            VerSig vs = new VerSig();
            PublicKey pub = vs.readPublicKey(args[0]);
            byte[] sigToVerify = vs.readSignature(args[1]);
            Signature sig = vs.getVerifySignature(pub);
            sig = vs.getFileSignature(sig, args[2]);
            boolean verifies = sig.verify(sigToVerify);
            System.out.println("Signature verifies: " + verifies);
        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
    }

}
