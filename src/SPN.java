/**
 * Created by xpf on 2015/8/31.
 */

// -------------------------------------------------------------------------

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

/**
 * This is an implementation of the SPN described in Section 3.2 of Stinson's
 * cryptography text.
 * <p/>
 * Example input: <89AC36B5> <FE26>
 *
 * @author Eric Hotinger
 * @version Nov 4, 2012
 */
public class SPN {

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

//        System.out.println(RSAAlg.modInverse(new BigInteger("28"),new BigInteger("75")));
        BigInteger before = new BigInteger(512, new Random());
        BigInteger en = rsaAlg.encryption(before);
        System.out.println(before);
        System.out.println(en);
        System.out.println(rsaAlg.decryption(en));

    }

}