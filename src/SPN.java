/**
 * Created by xpf on 2015/8/31.
 */

// -------------------------------------------------------------------------

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
        String k = "3a94d63f";
        String t = "26B7";

        String result = SPNAlg.realEncryption(t, k);
        System.out.println("Plain text is: " + t + "( Binary: " + SPNAlg.hexadecimalToBinary(SPNAlg.stringToStringArray(t)) + " )");
        System.out.println("Cipher text is: " + SPNAlg.binaryToHexadecimal(result) + "( Binary: "
                + result + " )");
        result = SPNAlg.binaryToHexadecimal(result);

        String res = SPNAlg.realDecryption(result, k);
        System.out.println(res);
    }

}