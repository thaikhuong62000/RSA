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

    public BigInteger encrypt(BigInteger bigInteger) {
        if (isModulusSmallerThanMessage(bigInteger)) {
            throw new IllegalArgumentException("Could not encrypt - message bytes are greater than modulus");
        }
        return Utils.powerMod(bigInteger, e, n);
    }

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

    public BigInteger decrypt(BigInteger encrypted) {
        return Utils.powerMod(encrypted, d, n);
    }

    public List<BigInteger> decrypt(List<BigInteger> encryption) {
        List<BigInteger> decryption = new ArrayList<BigInteger>();
        for (BigInteger bigInteger : encryption) {
            decryption.add(this.decrypt(bigInteger));
        }
        return decryption;
    }

    public BigInteger sign(BigInteger bigInteger) {
        return Utils.powerMod(bigInteger, d, n);
    }

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

    public BigInteger Verify(BigInteger signedMessage) {
        return signedMessage.modPow(e, n);
    }

    public List<BigInteger> verify(List<BigInteger> signedMessages) {
        List<BigInteger> verification = new ArrayList<BigInteger>();
        for (BigInteger bigInteger : signedMessages) {
            verification.add(this.Verify(bigInteger));
        }
        return verification;
    }

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
