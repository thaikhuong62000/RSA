import java.math.BigInteger;
import java.lang.ArithmeticException;

public class GCD {
    // Extended Euclidean Algorithm
    // Input: a, b > 0
    // Output: array
    // [0] : gcd(a,b)
    // [1] : x
    // [2] : y
    // Where a*x + b*y = gcd(a,b)
    public static BigInteger[] gcdExtended(BigInteger a, BigInteger b)
    {
        // Check exception
        if ((a.compareTo(BigInteger.ZERO) < 1) || (b.compareTo(BigInteger.ZERO) < 1)) {
            throw new ArithmeticException();
        }

        // Var decl
        BigInteger  x0 = BigInteger.ONE,
                    x1 = BigInteger.ZERO,
                    x = BigInteger.ZERO,
                    y0 = BigInteger.ZERO,
                    y1 = BigInteger.ONE,
                    y = BigInteger.ZERO;
        
        // Euclidean
        while (b.compareTo(BigInteger.ZERO) == 1) {
            BigInteger qr[] = a.divideAndRemainder(b);
            if (qr[1].compareTo(BigInteger.ZERO) == 0) {
                break;
            }
            x = x0.subtract(x1.multiply(qr[0]));
            y = y0.subtract(y1.multiply(qr[0]));
            a = b;
            b = qr[1];
            x0 = x1;
            x1 = x;
            y0 = y1;
            y1 = y;
        }
        
        BigInteger ans[] = {b, x, y};
        return ans;
    }
  
    // Example
    public static void main(String[] args)
    {
        BigInteger a = new BigInteger("29"), b = new BigInteger("8");
        BigInteger ans[] = gcdExtended(a, b);
        System.out.println(ans[0].toString());
        System.out.println(ans[1].toString());
        System.out.println(ans[2].toString());
    }
}