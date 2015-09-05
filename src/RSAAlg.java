import java.math.BigInteger;
import java.security.SecureRandom;
import java.sql.Time;
import java.util.Random;
import java.util.Timer;

/**
 * Created by xpf on 2015/9/4.
 */
public class RSAAlg {

    // these are my vain attempts to speed up the function by caching as much as
    // possible :P
    private static final BigInteger B_ONE = new BigInteger("1");
    private static final BigInteger B_ZERO = new BigInteger("0");
    private static final BigInteger B_TWO = new BigInteger("2");
    private static final BigInteger B_THREE = new BigInteger("3");
    private static Random random = new Random();

    private static BigInteger privateKey, publicKey, n;

    private int bitlen = 1024;


    public RSAAlg(int bitlen) {
        BigInteger p = getProbPrime(bitlen);
        BigInteger q = getProbPrime(bitlen);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        n = p.multiply(q);
        publicKey = new BigInteger("65537");
        privateKey = modInverse(publicKey, phi);
//        System.out.println(p.isProbablePrime(1) + " " + q.isProbablePrime(1));
//        System.out.println("\n private : " + privateKey + "\n" + publicKey.modInverse(phi));
//        boolean isPrivate = privateKey.equals(publicKey.modInverse(phi));
//        System.out.println("private same" + isPrivate);
//        SecureRandom random = new SecureRandom();
//        BigInteger p = new BigInteger(bitlen / 2, 100, random);
//
//        BigInteger q = new BigInteger(bitlen / 2, 100, random);
//        n = p.multiply(q);
//        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
//        publicKey = new BigInteger("65537");
//        privateKey = publicKey.modInverse(phi);
//        boolean isValid = publicKey.gcd(phi).equals(B_ONE);

//        System.out.println(isValid);

    }

    public static String generatorParameterOfRSA(int bitlen) {
        long start = System.currentTimeMillis();
        BigInteger p = getProbPrime(bitlen);
        BigInteger q = getProbPrime(bitlen);
        BigInteger phi = (p.subtract(B_ONE)).multiply(q.subtract(B_ONE));
        n = p.multiply(q);
        publicKey = new BigInteger("65537");
        privateKey = modInverse(publicKey, phi);
        long end = System.currentTimeMillis();
        long last = end - start;
        return "Public key is: " + "( " + n + ", " + publicKey + " ), "
                + "\n" + "Private key is: ( " + p + ", " + q + ", " + privateKey + " )"
                + "\n" + "using time for: " + last + "millis";
    }

    public BigInteger encryption(BigInteger massage) {
        return massage.modPow(publicKey, n);
    }

    public BigInteger decryption(BigInteger encrypted) {
        return encrypted.modPow(privateKey, n);
    }

//    public BigInteger encryption(String massage) {
//        return massage.modPow(publicKey, n);
//    }

//    public BigInteger decryption(String encrypted) {
//        return encrypted.modPow(privateKey, n);
//    }


    /**
     * Determines if a number is probably prime using the Miller-Rabin primality
     * test.
     *
     * @param number
     * @param iterations How accurate the test needs to be. Accuracy ~= 1 -
     *                   O(4^-iterations)
     * @return false if definitely composite. true if probably prime.
     */
    public static boolean isPrimeMillerRabin(BigInteger number, int iterations) {
        if (number.compareTo(B_ONE) <= 0) {
            // numbers less than or equal to 1 are not prime
            return false;
        } else if (number.getLowestSetBit() >= 1) {
            if (number.bitLength() == 2) {
                // 2 is prime
                return true;
            }
            // even numbers are not prime
            return false;
        } else if (number.equals(B_THREE)) {
            // 3 is prime
            return true;
        }
        // write number - 1 as 2^s * d, with d odd by factoring powers of 2 from
        // n-1
        BigInteger nMinusOne = number.subtract(B_ONE);
        int s = nMinusOne.getLowestSetBit();
        // while (nMinusOne.and(B_ONE.shiftLeft(s)).equals(B_ZERO))
        // {
        // ++s;
        // }
        BigInteger d = nMinusOne.divide(B_ONE.shiftLeft(s));
        // System.out.println("2^" + s + " * " + d);
        // if (iterations > number - 4)
        // {
        // iterations = number - 3;
        // }

        BigInteger nMinusThree = number.subtract(B_THREE);
        // r % (n-3) + 2
        for (int i = 1; i <= iterations; ++i) {
            // pick a random integer a in the range [2, n-2]
            BigInteger a = new BigInteger(nMinusOne.bitLength(), random).mod(nMinusThree).add(B_TWO);
            // long a = generator.nextInt(number - 3) + 2;
            // compute x=a^d % number, check to see if x==1 or x==number-1
            BigInteger x = a.modPow(d, number);
            if (x.equals(B_ONE) || x.equals(nMinusOne)) {
                continue;
            }
            boolean gotoLoop = false;
            for (int r = 1; r < s && !gotoLoop; ++r) {
                // x = x^2 % n
                x = x.modPow(B_TWO, number);
                if (x.equals(B_ONE)) {
                    return false;
                } else if (x.equals(nMinusOne)) {
                    gotoLoop = true;
                    break;
                }
            }
            if (!gotoLoop) {
                // definately composite
                return false;
            }
        }
        // probably prime
        return true;
    }

    public static BigInteger getProbPrime(int bit) {
        BigInteger p;
        do {
            p = new BigInteger(bit / 2, new SecureRandom());

        } while (!p.isProbablePrime(2));
        return p;

    }


    /**
     * Reads two command line parameters p and q and computes the a^-1 mod n
     * if it exists.
     *
     * @param k
     * @param n
     * @return
     */
    public static BigInteger modInverse(BigInteger k, BigInteger n) {
        BigInteger[] vals = gcd(k, n);
        BigInteger d = vals[0];
        BigInteger a = vals[1];
        BigInteger b = vals[2];
        if (d.compareTo(B_ONE) > 0) {
            System.out.println("Inverse does not exist.");
            return B_ZERO;
        }
        if (a.compareTo(B_ZERO) > 0) return a;
        return n.add(a);
    }

    static BigInteger[] gcd(BigInteger p, BigInteger q) {
        if (q.equals(B_ZERO)) return new BigInteger[]{p, B_ONE, B_ZERO};
        BigInteger[] vals = gcd(q, p.remainder(q));
        BigInteger d = vals[0];
        BigInteger a = vals[2];
        BigInteger b = vals[1].subtract(p.divide(q).multiply(vals[2]));

        return new BigInteger[]{d, a, b};
    }

}
