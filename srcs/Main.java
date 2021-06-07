package srcs;

import java.util.ArrayList;
import java.math.BigInteger;
import java.util.List;
import java.util.Scanner;


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
        Scanner sc= new Scanner(System.in);
        while (true)
        {
            System.out.println();
            System.out.println("0. Generate key: Generate private key and public key");
            System.out.println("   then write key to {fileName}.pri and {fileName}.pub");
            System.out.println("   Argument: fileName, keyLength");
            System.out.println("   Ex: 0 key 512");
            System.out.println();
            System.out.println("1. Encrypt file: Encrypt {filePath} and write encrypted");
            System.out.println("   file to {filePath}.enc");
            System.out.println("   Argument: filePath, publicKeyFilePath");
            System.out.println("   Ex: 1 file.txt key.pub");
            System.out.println();
            System.out.println("2. Decrypt file: Encrypt {filePath} and write decrypted");
            System.out.println("   file to {filePath}.dec");
            System.out.println("   Argument: filePath (without .enc), privateKeyFilePath");
            System.out.println("   Ex: 2 file.txt key.pri");
            System.out.println();
            System.out.println("3. Sign file: Encrypt {filePath} and write signed");
            System.out.println("   file to {filePath}.sig");
            System.out.println("   Argument: filePath, keyFilePath");
            System.out.println("   Ex: 3 file.txt key.pri");
            System.out.println();
            System.out.println("4. Verify file: Encrypt {filePath} and write verified");
            System.out.println("   file to {filePath}.veri");
            System.out.println("   Argument: filePath (without .sig), keyFilePath");
            System.out.println("   Ex: 4 file.txt key.pub");
            System.out.println();
            System.out.println("5. Exit");
            System.out.println();
            System.out.print("Please choose option: ");
            
            String arg = sc.nextLine();
            args = arg.split("\\s");
            
            int option;
            try {
                option = Integer.parseInt(args[0]);
            }
            catch (NumberFormatException e)
            {
                System.out.println("Invalid option!");
                continue;
            }

            if (option == 5) break;
            if ((option < 0) || (option > 4))
            {
                System.out.println("Invalid option!");
                continue;
            }
            else if (args.length != 3)
            {
                System.out.println("Invalid option!");
                continue;
            }
            List<BigInteger> publicKey, privateKey;
            switch (option) {
                case 0:
                    int keySize;
                    try {
                        keySize = Integer.parseInt(args[2]);
                    }
                    catch (NumberFormatException e)
                    {
                        System.out.println("Invalid option!");
                        continue;
                    }
                    if (keySize < 1)
                    {
                        System.out.println("Invalid option!");
                        continue;
                    }
                    generateKey(args[1], keySize);
                    break;
                case 1:
                    publicKey = RSA.readFromFile(args[2]);
                    enc_file(args[1], publicKey.get(0), publicKey.get(1));
                    break;
                case 2:
                    privateKey = RSA.readFromFile(args[2]);
                    dec_file(args[1], privateKey.get(0), privateKey.get(1));
                    break;
                case 3:
                    privateKey = RSA.readFromFile(args[2]);
                    sign_file(args[1], privateKey.get(0), privateKey.get(1));
                    break;
                case 4:
                    publicKey = RSA.readFromFile(args[2]);
                    verify_file(args[1], publicKey.get(0), publicKey.get(1));
                    break;
            }
        }
        sc.close();
    }
}
