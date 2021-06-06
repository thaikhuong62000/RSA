import java.math.BigInteger;
import java.lang.ArithmeticException;
import java.security.SecureRandom;
import srcs.Utils;

class test
{
    

     
    public static void main (String[] args)
    {
        BigInteger a = new BigInteger("516516561");
        BigInteger b = a.and(BigInteger.ONE);
        System.out.println(b);

    }
}