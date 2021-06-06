package srcs;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.security.SecureRandom;


public class Utils {

    private final static BigInteger first_prime_list[] = {
        new BigInteger("2"), new BigInteger("3"), new BigInteger("5"),
        new BigInteger("7"), new BigInteger("11"), new BigInteger("13"),
        new BigInteger("17"), new BigInteger("19"), new BigInteger("23"),
        new BigInteger("29"), new BigInteger("31"), new BigInteger("37"),
        new BigInteger("41"), new BigInteger("43"), new BigInteger("47"),
        new BigInteger("53"), new BigInteger("59"), new BigInteger("61"),
        new BigInteger("67"), new BigInteger("71"), new BigInteger("73"),
        new BigInteger("79"), new BigInteger("83"), new BigInteger("89"),
        new BigInteger("97"), new BigInteger("101"), new BigInteger("103"),
        new BigInteger("107"), new BigInteger("109"), new BigInteger("113"),
        new BigInteger("127"), new BigInteger("131"), new BigInteger("137"),
        new BigInteger("139"), new BigInteger("149"), new BigInteger("151"),
        new BigInteger("157"), new BigInteger("163"), new BigInteger("167"),
        new BigInteger("173"), new BigInteger("179"), new BigInteger("181"),
        new BigInteger("191"), new BigInteger("193"), new BigInteger("197"),
        new BigInteger("199"), new BigInteger("211"), new BigInteger("223"),
        new BigInteger("227"), new BigInteger("229"), new BigInteger("233"),
        new BigInteger("239"), new BigInteger("241"), new BigInteger("251"),
        new BigInteger("257"), new BigInteger("263"), new BigInteger("269"),
        new BigInteger("271"), new BigInteger("277"), new BigInteger("281"),
        new BigInteger("283"), new BigInteger("293"), new BigInteger("307"),
        new BigInteger("311"), new BigInteger("313"), new BigInteger("317"),
        new BigInteger("331"), new BigInteger("337"), new BigInteger("347")
    };

    /**
     * given a list of Strings split each of them in the middle
     *
     * @param messages
     * @return the list of splited strings
     * 
     * @author Rafael M. Pestano - Oct 15, 2012 7:15:19 PM
     */
    public static List<String> splitMessages(List<String> messages) {
        List<String> splitedMessages = new ArrayList<String>(messages.size() * 2);
        for (String message : messages) {
            int half = (int) Math.ceil(((double) message.length()) / ((double) 2));
            splitedMessages.add(message.substring(0, half));
            if (half < message.length()) {
                splitedMessages.add(message.substring(half, message.length()));
            }
        }

        return splitedMessages;
    }

    /**
     *
     * @param list
     * @return string representation of decrypted the message bytes
     * 
     * @author Rafael M. Pestano - Oct 15, 2012 7:15:19 PM
     */
    public static String bigIntegerToString(List<BigInteger> list) {
        StringBuilder plainText = new StringBuilder();
        for (BigInteger bigInteger : list) {
            plainText.append(new String(bigInteger.toByteArray()));
        }
        return plainText.toString();
    }

    /**
     *
     * @param list
     * @return decimal representation of encrypted/decrypted the message bytes
     * 
     * @author Rafael M. Pestano - Oct 15, 2012 7:15:19 PM
     */
    public static String bigIntegerSum(List<BigInteger> list) {
        BigInteger result = new BigInteger("0");
        for (BigInteger bigInteger : list) {
            result = result.add(bigInteger);
        }
        return result.toString();
    }

    /**
     *
     * @param x
     * @param y
     * 
     * @return x power y
     */
    public static BigInteger power(BigInteger x, BigInteger y)
    {
        BigInteger result = BigInteger.ONE;
        while (y.compareTo(BigInteger.ZERO) == 1)
        {
            if (y.and(BigInteger.ONE).compareTo(BigInteger.ZERO) == 0)
            {
                x = x.multiply(x);                    // If y is even
                y = y.shiftRight(1);
            }
            else
            {
                result = result.multiply(x);          // If y is odd
                y = y.subtract(BigInteger.ONE);
            }
        }
        return result;
    }

    /**
     *
     * @param x
     * @param y
     * @param p
     * @return (x power y) module p
     */
    public static BigInteger powerMod(BigInteger x, BigInteger y, BigInteger p)
    {
        BigInteger res = BigInteger.ONE;

        x = x.mod(p); // Update x if it is more than or equal to p

        if (x.compareTo(BigInteger.ZERO) == 0)
            return BigInteger.ZERO; // In case x is divisible by p;

        while (y.compareTo(BigInteger.ZERO) == 1)
        {
            // If y is odd, multiply x with result
            if ((y.and(BigInteger.ONE)).compareTo(BigInteger.ZERO) != 0)
                res = res.multiply(x).mod(p);

            // y must be even now
            y = y.shiftRight(1); // y = y/2
            x = x.multiply(x).mod(p);
        }
        return res;
    }
    
    /**
     *
     * @param a
     * @param b
     * @return GCD(a, b)
     */
    public static BigInteger gcd(BigInteger a, BigInteger b)
    {
        while (b.compareTo(BigInteger.ZERO) != 0)
        {
            BigInteger temp = b;
            b = a.mod(b);
            a = temp;
        }
        return a;
    }

    /**
     * Extended Euclidean Algorithm
     * @param a > 0             ~ e
     * @param b > 0             ~ ø(n)
     * @return d
     * Where e*d=1 mod ø(n)
     */
    public static BigInteger gcdExtended(BigInteger a, BigInteger b)
    {
        BigInteger y0 = new BigInteger("0");
        BigInteger y1 = new BigInteger("1");
        BigInteger r, q;
        BigInteger y = BigInteger.ONE;

        while (a.compareTo(BigInteger.ZERO) == 1)
        {
            r = b.mod(a);
            if (r.compareTo(BigInteger.ZERO) == 0)
                break;
            q = b.divide(a);
            y = y0.subtract(y1.multiply(q));
            y0 = y1;
            y1 = y;
            b = a;
            a = r;
        }
        if (a.compareTo(BigInteger.ONE) == 1)
            return BigInteger.ZERO;
        else
            return y;
    }

    
    /**
     * Random a odd integer with n-bit-length
     * @param Size
     * @return BigInteger
     */
    public static BigInteger randomGeneration(int n)
    {
        n = n / 8;
        if (n == 0) n = 1;
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[n];
        random.nextBytes(bytes);
        while (true)
        {
            if (bytes[0] < 0)
            {
                random.nextBytes(bytes);
                continue;
            }
            if (bytes[n - 1] % 2 == 0)
            {
                random.nextBytes(bytes);
                continue;
            }
            break;
        }
        return new BigInteger(bytes);
    }

    /**
     * Generate a probably prime number with n-bit-length
     * @param Size
     * @return BigInteger
     */
    public static BigInteger getLowLevelPrime(int n)
    {
        BigInteger pc;
        while (true)
        {
            pc = randomGeneration(n);
            boolean flag = true;
            for (BigInteger divisor:Utils.first_prime_list)
            {
                if ((pc.mod(divisor).compareTo(BigInteger.ZERO) == 0)
                    && !(divisor.multiply(divisor).compareTo(pc) == 1))
                {
                    flag = false;
                    break;
                }
            }
            if (flag) return pc;
        }
    }

    /**
     * Function to check if a number mrc is composite
     * Helper for {@link Utils#isMillerRabinPassed(BigInteger, int)}
     */
    public static boolean trialComposite(BigInteger rt, BigInteger ec, BigInteger mrc, BigInteger max)
    {
        BigInteger One = BigInteger.ONE;
        if (powerMod(rt, ec, mrc).compareTo(One) == 0)
            return false;
        for (BigInteger i = BigInteger.ZERO; i.compareTo(max) == -1; i = i.add(One))
        {
            if (powerMod(rt, power(new BigInteger("2"), i).multiply(ec), mrc).compareTo(mrc.subtract(One)) == 0)
                return false;
        }
        return true;
    }

    /**
     * Check if a probably prime number is a prime number
     * @param number
     * @param Size (bit-length)
     * @return BigInteger
     */
    public static boolean isMillerRabinPassed(BigInteger mrc, int size)
    {
        BigInteger maxDivisionsByTwo = BigInteger.ZERO;
        BigInteger ec = mrc.subtract(BigInteger.ONE);
        while (ec.and(BigInteger.ONE).compareTo(BigInteger.ZERO) == 0)
        {
            ec = ec.shiftRight(1);
            maxDivisionsByTwo = maxDivisionsByTwo.add(BigInteger.ONE);
        }
        if (power(new BigInteger("2"), maxDivisionsByTwo).multiply(ec).compareTo(mrc.subtract(BigInteger.ONE)) != 0)
            return false;
    
        
        for (int i = 0; i < 20; i++)
        {
            BigInteger round_tester = randomGeneration(size / 2);
            if (trialComposite(round_tester, ec, mrc, maxDivisionsByTwo))
                return false;
        }
        return true;
    }

    /**
     * Random a n-bit-length-prime-number
     * Method: random probably prime number then check with Miller Rabin method
     * 
     * @param n : Size
     * @return BigInteger
     */
    public static BigInteger primeGeneration(int n)
    {
        while (true)
        {
            BigInteger prime_candidate = getLowLevelPrime(n);
            if (!isMillerRabinPassed(prime_candidate, n))
                continue;
            else
                return prime_candidate;
        }
    }

    /**
     * Generate e 
     * @param phi
     * @return e
     */
    public static BigInteger eGeneration(BigInteger phi)
    {
        BigInteger temp = new BigInteger("3");

        while (true)
        {
            BigInteger gcdValue;
            gcdValue = gcd(phi, temp);
            if (gcdValue.compareTo(BigInteger.ONE) == 0)
            {
                break;
            }
            temp = temp.add(new BigInteger("2"));
        }
        return temp;
    }

    /**
     * Calculate d by using {@link #gcdExtended(BigInteger, BigInteger)}
     * 
     * @param e
     * @param phi
     * @return d
     */
    public static BigInteger calculateD(BigInteger e, BigInteger phi)
    {
        BigInteger ans;
        ans = gcdExtended(e, phi);
        if (ans.compareTo(BigInteger.ZERO) == -1)
            ans = ans.add(phi);
        return ans;
    }

}
