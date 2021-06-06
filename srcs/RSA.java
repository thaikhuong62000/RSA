package srcs;

import java.io.BufferedWriter;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Implementation of RSA encription algorithm
 * http://en.wikipedia.org/wiki/RSA_(algorithm
 *
 * @author Rafael M. Pestano - Oct 15, 2012 7:15:19 PM
 */
public class RSA {

    private final static BigInteger ONE = BigInteger.ONE;
    private BigInteger d;
    private BigInteger e; //part of public key - relative prime of phi 
    private BigInteger n; //part of public key obtained with n = p*q
    private BigInteger p; //prime
    private BigInteger q; //prime
    private BigInteger phi;// obtained with phi = (p-1)*(q-1)

    RSA() {}

    RSA(BigInteger p, BigInteger q, BigInteger e) {

        phi = (p.subtract(ONE)).multiply(q.subtract(ONE));  // phi = (p-1)*(q-1) 
        this.e = e;
        this.p = p;
        this.q = q;
        n = p.multiply(q);
        d = Utils.calculateD(e, phi);  // d = e^-1 mod phi
    }

    public void initPublicKey(BigInteger e, BigInteger n)
    {
        this.e = e;
        this.n = n;
    }

    public void initPrivateKey(BigInteger d, BigInteger n)
    {
        this.d = d;
        this.n = n;
    }

    /**
     * Encrypts a message through <b>C = M^e mod n</b> where: <ul> <li>C =
     * encrypted message <li>M = message to be encrypted <li>e = relative prime
     * to phi <li>n = modulo obtained from p*q </ui>
     *
     * @param message to be encrypted
     * @return encrypted message represented by a Java BigInteger
     * 
     * @author Rafael M. Pestano - Oct 15, 2012 7:15:19 PM
     */
    public BigInteger encrypt(BigInteger bigInteger) {
        if (isModulusSmallerThanMessage(bigInteger)) {
            throw new IllegalArgumentException("Could not encrypt - message bytes are greater than modulus");
        }
        return Utils.powerMod(bigInteger, e, n);
    }

    /**
     * Encrypts a message using the encrypt method checking if message blocks
     * are valid
     *
     * @see RSAImpl#getValidEncryptionBlocks(java.util.List)
     * @see RSAImpl#encrypt(java.math.BigInteger)
     * @param message string
     * @return a list of encrypted message blocks where each encrypted block is represented by a Java BigInteger
     * 
     * @author Rafael M. Pestano - Oct 15, 2012 7:15:19 PM
     */
    public List<BigInteger> encryptMessage(final String message) {
        List<BigInteger> toEncrypt = new ArrayList<BigInteger>();
        BigInteger messageBytes = new BigInteger(message.getBytes());
        if (isModulusSmallerThanMessage(messageBytes)) {
            toEncrypt = getValidEncryptionBlocks(Utils.splitMessages(new ArrayList<String>() {
                {
                    add(message);
                }
            }));
        } else {
            toEncrypt.add((messageBytes));
        }
        List<BigInteger> encrypted = new ArrayList<BigInteger>();
        for (BigInteger bigInteger : toEncrypt) {
            encrypted.add(this.encrypt(bigInteger));
        }
        return encrypted;
    }

    /**
     * encript each line of a file using the encript method
     *
     * @param filePath path to a file containing the message to be encripted
     * @return a BigInteger representing each encrypted file line
     * 
     * @author Rafael M. Pestano - Oct 15, 2012 7:15:19 PM
     */
    public List<BigInteger> encryptFile(String filePath) {
        BufferedReader br = null;
        FileInputStream fis = null;
        String line = "";
        List<BigInteger> encription = new ArrayList<BigInteger>();
        try {
            fis = new FileInputStream(new File(filePath));
            br = new BufferedReader(new InputStreamReader(fis, Charset.forName("UTF-8")));
            String temp = "";
            while ((line = br.readLine()) != null) {
                if ("".equals(line)) {
                    temp += "\n";
                    continue;
                }
                encription.addAll(this.encryptMessage(temp + line));
                temp = "\n";
            }
            encription.addAll(this.encryptMessage(temp));

        } catch (IOException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                if (fis != null) {
                    fis.close();
                }
                if (br != null) {
                    br.close();
                }

            } catch (IOException ex) {
                Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return encription;

    }

    /**
     * decrypt an encrypted message through <b>M = C^d mod n</b> where: <ul>
     * <li>M = decrypted message <li>C = encrypted message <li>d = private key -
     * obtained from multiplicative inverse of 'e' mod 'phi' <li>n = modulo -
     * obtained from p*q </ul>
     *
     * @param encrypted encrypted message
     * @return decrypted message represented by a Java BigInteger type
     * 
     * @author Rafael M. Pestano - Oct 15, 2012 7:15:19 PM
     */
    public BigInteger decrypt(BigInteger encrypted) {
        return Utils.powerMod(encrypted, d, n);
    }

    /**
     * decrypt a list of encrypted messages through <b>M = C^d mod n</b> where:
     * <ul> <li>M = decrypted message <li>C = encrypted message <li>d = private
     * key - obtained from multiplicative inverse of 'e' mod 'phi' <li>n =
     * modulo - obtained from p*q </ul>
     *
     * @param encryption encrypted messages represented by a list of Java BigInteger
     * @return list of decrypted message
     * 
     * @author Rafael M. Pestano - Oct 15, 2012 7:15:19 PM
     */
    public List<BigInteger> decrypt(List<BigInteger> encryption) {
        List<BigInteger> decryption = new ArrayList<BigInteger>();
        for (BigInteger bigInteger : encryption) {
            decryption.add(this.decrypt(bigInteger));
        }
        return decryption;
    }

    /**
     * digitally signs a message through <b>A = M^d mod n</b> where: <ul> <li>A
     * = signed message <li>M = message to be digitally signed <li>d = private
     * key - obtained from multiplicative inverse of 'e' mod 'phi' <li>n =
     * modulo - obtained from p*q </ul>
     *
     * @param message to be digitally signed
     * @return signed message represented by a Java BigInteger
     * 
     * @author Rafael M. Pestano - Oct 15, 2012 7:15:19 PM
     */
    public BigInteger sign(BigInteger bigInteger) {
        return Utils.powerMod(bigInteger, d, n);
    }

    /**
     * Signs a message using the sign method checking if message blocks are
     * valid
     *
     * @see RSAImpl#getValidEncryptionBlocks(java.util.List)
     * @see RSAImpl#sign(java.math.BigInteger)
     * @param message string
     * @return a list of signed message blocks where each signed block is represented by a Java BigInteger
     * 
     * @author Rafael M. Pestano - Oct 15, 2012 7:15:19 PM
     */
    public List<BigInteger> signMessage(final String message) {
        List<BigInteger> toSign = new ArrayList<BigInteger>();
        BigInteger messageBytes = new BigInteger(message.getBytes());
        if (isModulusSmallerThanMessage(messageBytes)) {
            toSign = getValidEncryptionBlocks(Utils.splitMessages(new ArrayList<String>() {
                {
                    add(message);
                }
            }));
        } else {
            toSign.add((messageBytes));
        }
        List<BigInteger> signed = new ArrayList<BigInteger>();
        for (BigInteger bigInteger : toSign) {
            signed.add(this.sign(bigInteger));
        }
        return signed;
    }

    /**
     * Signs each line of a file using the sign method
     * @see RSA#signMessage(java.lang.String) 
     * @param filePath
     * @return a BigInteger representing each signed lines
     * 
     * @author Rafael M. Pestano - Oct 15, 2012 7:15:19 PM
     */
    public List<BigInteger> signFile(String filePath) {
        BufferedReader br = null;
        FileInputStream fis = null;
        String line = "";
        List<BigInteger> signedLines = new ArrayList<BigInteger>();
        try {
            fis = new FileInputStream(new File(filePath));
            br = new BufferedReader(new InputStreamReader(fis, Charset.forName("UTF-8")));
            String temp = "";
            while ((line = br.readLine()) != null) {
                if ("".equals(line)) {
                    temp += "\n";
                    continue;
                }
                signedLines.addAll(this.signMessage(temp + line));
                temp = "\n";
            }
            signedLines.addAll(this.signMessage(temp));

        } catch (IOException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                if (fis != null) {
                    fis.close();
                }
                if (br != null) {
                    br.close();
                }

            } catch (IOException ex) {
                Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return signedLines;
    }

    /**
     * verifies a signed message through <b>A^e mod n = M</b> where: <ul> <li>A
     * = signed message <li>e = relative prime to phi <li>n = modulo - obtained
     * from p*q <li>M = original message </ul>
     *
     * @param message to be verified
     * @return decimal number result from verification , if its equal to the
     * decimal representation of the original message then its successfully
     * verified
     * @see RSA#isVerified(java.math.BigInteger, java.math.BigInteger)
     * 
     * @author Rafael M. Pestano - Oct 15, 2012 7:15:19 PM
     */
    public BigInteger Verify(BigInteger signedMessage) {
        return signedMessage.modPow(e, n);
    }

    /**
     * verifies a list of signed messages through verify method
     *
     * @param signedMessages
     * @return list of verified messages
     * @see RSA#Verify(java.math.BigInteger)
     * 
     * @author Rafael M. Pestano - Oct 21, 2012 7:15:19 PM
     */
    public List<BigInteger> verify(List<BigInteger> signedMessages) {
        List<BigInteger> verification = new ArrayList<BigInteger>();
        for (BigInteger bigInteger : signedMessages) {
            verification.add(this.Verify(bigInteger));
        }
        return verification;
    }

    /**
     * @param signedMessage
     * @param original message
     * @return <code>true</code> if decimal representation of the original
     * message matched the decimal representation of the signed message
     * <code>false</code> otherwise
     *
     * @see RSA#Verify(java.math.BigInteger)
     * 
     * @author Rafael M. Pestano - Oct 21, 2012 7:15:19 PM
     */
    public boolean isVerified(BigInteger signedMessage, BigInteger message) {
        return this.Verify(signedMessage).equals(message);
    }

    /**
     * ensures that blocks to encrypt are smaller than modulus
     *
     * @param messages list of blocks to be splited at half recursively
     * @return list of valid blocs
     *
     * @author Rafael M. Pestano - Oct 21, 2012 7:15:19 PM
     */
    public List<BigInteger> getValidEncryptionBlocks(List<String> messages) {
        List<BigInteger> validBlocks = new ArrayList<BigInteger>();
        BigInteger messageBytes = new BigInteger(messages.get(0).getBytes());
        if (!isModulusSmallerThanMessage(messageBytes)) {
            for (String msg : messages) {
                validBlocks.add(new BigInteger(msg.getBytes()));
            }
            return validBlocks;
        } else {//message is bigger than modulus so we have o split it
            return getValidEncryptionBlocks(Utils.splitMessages(messages));
        }

    }

    /**
     * @param message
     * @return decimal representation of the message
     * 
     * @author Rafael M. Pestano - Oct 21, 2012 7:15:19 PM
     */
    public List<BigInteger> messageToDecimal(final String message) {
        List<BigInteger> toDecimal = new ArrayList<BigInteger>();
        BigInteger messageBytes = new BigInteger(message.getBytes());
        if (isModulusSmallerThanMessage(messageBytes)) {
            toDecimal = getValidEncryptionBlocks(Utils.splitMessages(new ArrayList<String>() {
                {
                    add(message);
                }
            }));
        } else {
            toDecimal.add((messageBytes));
        }
        List<BigInteger> decimal = new ArrayList<BigInteger>();
        for (BigInteger bigInteger : toDecimal) {
            decimal.add(bigInteger);
        }
        return decimal;
    }

    /**
     * @param filePath
     * @return decimal representation of a file
     * 
     * @author Rafael M. Pestano - Oct 21, 2012 7:15:19 PM
     */
    public List<BigInteger> fileToDecimal(final String filePath) {
        BufferedReader br = null;
        FileInputStream fis = null;
        String line = "";
        List<BigInteger> decimalLines = new ArrayList<BigInteger>();
        try {
            fis = new FileInputStream(new File(filePath));
            br = new BufferedReader(new InputStreamReader(fis, Charset.forName("UTF-8")));

            while ((line = br.readLine()) != null) {
                if ("".equals(line)) {
                    continue;
                }
                decimalLines.addAll(this.messageToDecimal(line));
            }

        } catch (IOException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                if (fis != null) {
                    fis.close();
                }
                if (br != null) {
                    br.close();
                }

            } catch (IOException ex) {
                Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return decimalLines;
    }

    private boolean isModulusSmallerThanMessage(BigInteger messageBytes) {
        return n.compareTo(messageBytes) == -1;
    }

    @Override
    public String toString() {
        String s = "";
        s += "p                     = " + p + "\n";
        s += "q                     = " + q + "\n";
        s += "e                     = " + e + "\n";
        s += "private               = " + d + "\n";
        s += "modulus               = " + n;
        return s;
    }

    /**
     * @param filePath
     * @return decimal representation of a file
     */
    public static List<BigInteger> readFromFile(String filePath)
        throws NumberFormatException
    {
        BufferedReader br = null;
        FileInputStream fis = null;
        String line = "";
        List<BigInteger> fileString = new ArrayList<BigInteger>();
        try {
            fis = new FileInputStream(new File(filePath));
            br = new BufferedReader(new InputStreamReader(fis, Charset.forName("UTF-8")));

            while ((line = br.readLine()) != null) {
                if ("".equals(line)) {
                    continue;
                }
                String words[] = line.split("\\s");
                for (String w:words)
                {
                    fileString.add(new BigInteger(w));
                }
            }

        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            try {
                if (fis != null) {
                    fis.close();
                }
                if (br != null) {
                    br.close();
                }

            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        return fileString;
    }

    /**
     * Write message to file
     * 
     * @param message
     * @param filePath
     */
    public static void writeBigIntegerToFile(List<BigInteger> message, String filePath)
    {
        BufferedWriter bw = null;
        FileOutputStream fis = null;
        try {
            fis = new FileOutputStream(new File(filePath));
            bw = new BufferedWriter(new OutputStreamWriter(fis, Charset.forName("UTF-8")));
            for (BigInteger s:message)
            {
                bw.write(s.toString());
                bw.write('\n');
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            try {
                if (bw != null) {
                    bw.close();
                }
                if (fis != null) {
                    fis.close();
                }

            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }


    public static void writeStringToFile(String message, String filePath)
    {
        BufferedWriter bw = null;
        FileOutputStream fis = null;
        try {
            fis = new FileOutputStream(new File(filePath));
            bw = new BufferedWriter(new OutputStreamWriter(fis, Charset.forName("UTF-8")));
            bw.write(message);
        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            try {
                if (bw != null) {
                    bw.close();
                }
                if (fis != null) {
                    fis.close();
                }

            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }
}
