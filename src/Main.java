/**
 * Created by xpf on 2015/8/31.
 */

// -------------------------------------------------------------------------

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * This is an implementation of the Main described in Section 3.2 of Stinson's
 * cryptography text.
 * <p/>
 * Example input: <89AC36B5> <FE26>
 *
 * @author Eric Hotinger
 * @version Nov 4, 2012
 */
public class Main {

    public static void main(String[] args) {
//        long start = System.currentTimeMillis();
//        String k = "3a94d63f";
//        String t = "26B7";
//
//        String result = SPNAlg.realEncryption(t, k);
//        System.out.println("Plain text is: " + t + "( Binary: " + SPNAlg.hexadecimalToBinary(SPNAlg.stringToStringArray(t)) + " )");
//        System.out.println("Cipher text is: " + SPNAlg.binaryToHexadecimal(result) + "( Binary: "
//                + result + " )");
//        result = SPNAlg.binaryToHexadecimal(result);
//
//        String res = SPNAlg.realDecryption(result, k);
//        long end = System.currentTimeMillis();
//        long last = end - start;
//        System.out.println("TIME: " + last + "millis");
//        System.out.println("After decryption: " + res + "( Binary: "
//                + SPNAlg.hexadecimalToBinary(SPNAlg.stringToStringArray(res)) + " )");
//        System.out.println(RSAAlg.generatorParameterOfRSA(1024));

        RSAAlg rsaAlg = new RSAAlg(1024);

        BigInteger before = new BigInteger(512, new SecureRandom());
        long start = System.currentTimeMillis();
        BigInteger en = rsaAlg.encryption(before);
        long end = System.currentTimeMillis();
        long last = end - start;
        System.out.println("Time for encryption: " + last + "millis");
        System.out.println("PlainText :" + before);
        System.out.println("CypherText :" + en);
        long a = System.currentTimeMillis();
        System.out.println("DecryptionText :" + rsaAlg.decryption(en));
        long b = System.currentTimeMillis();
        long c = b - a;
        System.out.println("Time for decryption: " + c + "millis");

        BigInteger fast = rsaAlg.encryptionCRT(before);
        System.out.println(before);
        System.out.println(fast);
        long e = System.currentTimeMillis();
        System.out.println("CRT Decryption: " + rsaAlg.decryptionCRT(en));
        long f = System.currentTimeMillis();
        long g = f - e;
        System.out.println("fast decryption: " + g + "millis");

//        String plainTExt = "Fuck Youaskldflsdakhfkjashdjhfkjashkslhjfkashdfhha";
//        String ens = rsaAlg.encryption(plainTExt);
//        System.out.println(ens);
//        long h = System.currentTimeMillis();
//        System.out.println(rsaAlg.decryption(ens));
//        long i = System.currentTimeMillis();
//        long j = i - h;
//        System.out.println("Time (String): " + j + "millis");

//        long k = System.currentTimeMillis();
//        long l = System.currentTimeMillis();
//        long m = l - k;
//        System.out.println("Time (String) fast:" + m + "millis");

    }

}