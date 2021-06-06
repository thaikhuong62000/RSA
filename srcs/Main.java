package srcs;
import java.util.ArrayList;

import java.math.BigInteger;
import java.util.List;


public class Main {

    /**
     * Generate public key and private key and write 
     * to two file {fileName}.pub and {fileName}.pri
     * 
     * @param fileName
     * @param keySize
     * 
     */
    public static void generateKey(String fileName, int keySize)
    {
        long start = System.currentTimeMillis();
        BigInteger p = Utils.primeGeneration(keySize);
        BigInteger q = Utils.primeGeneration(keySize);
        while (q.compareTo(p) == 0)
            q = Utils.primeGeneration(keySize);
        BigInteger n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        BigInteger e = Utils.eGeneration(phi);
        BigInteger d = Utils.calculateD(e, phi);
        List<BigInteger> publicKey = new ArrayList<BigInteger>();
        publicKey.add(e);
        publicKey.add(n);
        RSA.writeBigIntegerToFile(publicKey, fileName + ".pub");
        List<BigInteger> privateKey = new ArrayList<BigInteger>();
        privateKey.add(d);
        privateKey.add(n);
        RSA.writeBigIntegerToFile(privateKey, fileName + ".pri");
        long end = System.currentTimeMillis();
        long elapsedTime = end - start;
        System.out.println("Generate key complete!");
        System.out.println("Elapsed Time: " + elapsedTime + "ms");
    }

    /**
     * Encrypt a file then write encrypted file to {filePath}.enc
     * 
     * @param filePath
     * @param e - part of public key
     * @param n - part of public key
     * @return encrypted message
     */
    public static List<BigInteger> enc_file(String filePath, BigInteger e, BigInteger n)
    {
        long start = System.currentTimeMillis();
        RSA RSA_enc = new RSA();
        RSA_enc.initPublicKey(e, n);
        List<BigInteger> encryption;
        encryption = RSA_enc.encryptFile(filePath);
        // System.out.println("encripted(decimal)    = " + Utils.bigIntegerSum(encryption));
        RSA.writeBigIntegerToFile(encryption, filePath + ".enc");
        long end = System.currentTimeMillis();
        long elapsedTime = end - start;
        System.out.println("Encrypt file complete!");
        System.out.println("Elapsed Time: " + elapsedTime + "ms");
        return encryption;
    }

    /**
     * Decrypt a file then write decrypted file to {filePath}.dec
     * 
     * @param filePath
     * @param d - part of private key
     * @param n - part of private key
     * @return decrypted message
     */
    public static String dec_file(String filePath, BigInteger d, BigInteger n)
    {
        long start = System.currentTimeMillis();
        String decrypted = "";
        try {
            List<BigInteger> encripted = RSA.readFromFile(filePath + ".enc");
            RSA RSA_enc = new RSA();
            RSA_enc.initPrivateKey(d, n);
            List<BigInteger> decrypt;
            decrypt = RSA_enc.decrypt(encripted);
            decrypted = Utils.bigIntegerToString(decrypt);
            // System.out.println("decrypted(plain text) = " + decrypted);
            // System.out.println("decrypted(decimal)    = " + Utils.bigIntegerSum(decrypt));
            RSA.writeStringToFile(decrypted, filePath + ".dec");
        }
        catch (NumberFormatException ex) {
            System.out.println("Invalid file!");
        } finally {
            long end = System.currentTimeMillis();
            long elapsedTime = end - start;
            System.out.println("Decrypt file complete!");
            System.out.println("Elapsed Time: " + elapsedTime + "ms");
        }
        return decrypted;
    }

    /**
     * Sign a file then write signed file to {filePath}.sig
     * 
     * @param filePath
     * @param d - part of private key
     * @param n - part of private key
     * @return signed message
     */
    public static List<BigInteger> sign_file(String filePath, BigInteger d, BigInteger n)
    {
        long start = System.currentTimeMillis();
        RSA RSA_sign= new RSA();
        RSA_sign.initPrivateKey(d, n);
        List<BigInteger> signed;
        signed = RSA_sign.signFile(filePath);
        // System.out.println("signed(decimal)    = " + Utils.bigIntegerSum(signed));
        RSA.writeBigIntegerToFile(signed, filePath + ".sig");
        long end = System.currentTimeMillis();
        long elapsedTime = end - start;
        System.out.println("Signed file complete!");
        System.out.println("Elapsed Time: " + elapsedTime + "ms");
        return signed;
    }

    /**
     * Verify a file then write verified file to {filePath}.veri
     * 
     * @param filePath
     * @param e - part of public key
     * @param n - part of public key
     * @return verified message
     */
    public static String verify_file(String filePath, BigInteger e, BigInteger n)
    {
        long start = System.currentTimeMillis();
        String verifiedString = "";
        try {
            List<BigInteger> signed = RSA.readFromFile(filePath + ".sig");
            RSA RSA_enc = new RSA();
            RSA_enc.initPublicKey(e, n);
            List<BigInteger> verified;
            verified = RSA_enc.verify(signed);
            verifiedString = Utils.bigIntegerToString(verified);
            // System.out.println("verified(plain text) = " + decrypted);
            // System.out.println("verified(decimal)    = " + Utils.bigIntegerSum(verified));
            RSA.writeStringToFile(verifiedString, filePath + ".veri");
        } catch (NumberFormatException ex) {
            System.out.println("Invalid file!");
        } finally {
            long end = System.currentTimeMillis();
            long elapsedTime = end - start;
            System.out.println("Decrypt file complete!");
            System.out.println("Elapsed Time: " + elapsedTime + "ms");
        }
        return verifiedString;
    }


    public static void test()
    {
        BigInteger p;
        BigInteger q;
        BigInteger e;
        final String message;
        boolean isFile = false;

        p = new BigInteger("5700734181645378434561188374130529072194886062117");
        q = new BigInteger("35894562752016259689151502540913447503526083241413");
        e = new BigInteger("33445843524692047286771520482406772494816708076993");

        message = "This is a test";
        
        p = new BigInteger("101"); 
        q = new BigInteger("113");
        e = new BigInteger("3533");


        RSA RSA = new RSA(p, q, e);

        List<BigInteger> encryption;
        List<BigInteger> signed;
        List<BigInteger> decimalMessage;
        if(isFile){
            encryption = RSA.encryptFile(message);
            signed = RSA.signFile(message);
            decimalMessage = RSA.fileToDecimal(message);
        } else {
            encryption = RSA.encryptMessage(message);
            signed = RSA.signMessage(message);
            decimalMessage = RSA.messageToDecimal(message);
        }

        List<BigInteger> decrypt = RSA.decrypt(encryption);
        List<BigInteger> verify = RSA.verify(signed);
        System.out.println();
        System.out.println("message(plain text)   = " + Utils.bigIntegerToString(decimalMessage));
        System.out.println("message(decimal)      = " + Utils.bigIntegerSum(decimalMessage));
        System.out.println("encripted(decimal)    = " + Utils.bigIntegerSum(encryption));
        System.out.println("decrypted(plain text) = " + Utils.bigIntegerToString(decrypt));
        System.out.println("decrypted(decimal)    = " + Utils.bigIntegerSum(decrypt));
        System.out.println("signed(decimal)       = " + Utils.bigIntegerSum(signed));
        System.out.println("verified(plain text)  = " + Utils.bigIntegerToString(verify));
        System.out.println("verified(decimal)     = " + Utils.bigIntegerSum(verify));
    }

    public static void main(String[] args)
    {
        // test();
        // generateKey("key", 500);
        String filePath = "file.txt";
        List<BigInteger> publicKey = RSA.readFromFile("key.pub");
        List<BigInteger> privateKey = RSA.readFromFile("key.pri");
        sign_file(filePath, privateKey.get(0), privateKey.get(1));
        verify_file(filePath, publicKey.get(0), publicKey.get(1));
        enc_file(filePath, publicKey.get(0), publicKey.get(1));
        dec_file(filePath, privateKey.get(0), privateKey.get(1));
    }

}
