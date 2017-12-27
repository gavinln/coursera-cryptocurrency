// From the Java tutorial: Generating & Verifying signatures
// https://docs.oracle.com/javase/tutorial/security/apisign/index.html

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.BufferedInputStream;
import java.io.IOException;

import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.InvalidKeyException;
import java.security.SignatureException;

class GenSig {
    private class Keys {
        PublicKey pub;
        PrivateKey priv;

        public Keys(PublicKey pub, PrivateKey priv) {
            super();
            this.pub = pub;
            this.priv = priv;
        }

        @Override
        public String toString() {
            return String.format("(%s, %s)", this.pub, this.priv);
        }
    }

    public Keys getKeys() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(
                "DSA", "SUN");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");

            keyGen.initialize(1024, random);
            KeyPair pair = keyGen.generateKeyPair();

            PrivateKey priv = pair.getPrivate();
            PublicKey pub = pair.getPublic();
            return new Keys(pub, priv);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    public Signature getSignature(PrivateKey priv) {
        Signature dsa = null;
        try {
            dsa = Signature.getInstance("SHA1withDSA", "SUN");
            dsa.initSign(priv);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return dsa;
    }

    public byte[] signFile(Signature dsa, String fileName) {
        byte[] signature = null;
        try {
            FileInputStream fis = new FileInputStream(fileName);
            BufferedInputStream bufin = new BufferedInputStream(fis);
            byte[] buffer = new byte[1024];
            int len;
            while ((len = bufin.read(buffer)) >= 0) {
                dsa.update(buffer, 0, len);
            };
            bufin.close();
            signature = dsa.sign();

        } catch(SignatureException e) {
            e.printStackTrace();
        } catch(IOException e) {
            e.printStackTrace();
        }
        return signature;
    }

    public void saveSignature(byte[] fileSig) {
        try {
            FileOutputStream sigfos = new FileOutputStream("sig");
            sigfos.write(fileSig);
            sigfos.close();
        } catch(IOException e) {
            e.printStackTrace();
        }
    }

    public void savePublicKey(PublicKey pub) {
        try {
            FileOutputStream keyfos = new FileOutputStream("public_key");
            keyfos.write(pub.getEncoded());
            keyfos.close();
        } catch(IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        /* Generate a DSA signature */
        if (args.length != 1) {
            System.out.println("Usage: GenSig nameOfFileToSign");
        }
        else try {
            GenSig gs = new GenSig();
            Keys keys = gs.getKeys();
            Signature sig = gs.getSignature(keys.priv);
            byte[] fileSig = gs.signFile(sig, args[0]);
            gs.saveSignature(fileSig);
            gs.savePublicKey(keys.pub);
            System.out.println("Generated and saved signature & public key");

        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
    }
}
