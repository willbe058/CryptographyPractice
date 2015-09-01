
import java.math.BigInteger;
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
public class SPNAlg {
    /**
     * Error message that will be printed if the program has incorrect
     * arguments.
     */
    static final String ERROR_MESSAGE =
            "ERROR: Incorrect program usage.\nPlease use: SPN <key> <plain-text>";

    /**
     * Defines what round the program is currently on.
     */
    static int currentRound = 0;

    static int deRound = 0;

    // ----------------------------------------------------------

    public static String realEncryption(String t, String k) {


        String[] ts;
        if (t.length() % 4 == 0) {
            ts = new String[t.length() / 4];
            if (t.length() > 4) {

                int start = 0;
                int initLength = 4;
                for (int i = 0; i < t.length() / 4; i++) {
                    if (initLength < t.length()) {
                        ts[i] = t.substring(start, initLength);
                        start = initLength;
                        initLength = initLength + 4;
                    } else {
                        initLength = t.length();
                        ts[i] = t.substring(start, initLength);
                    }

                }
            } else {
                ts = new String[]{t};
            }
        } else {
            ts = new String[t.length() / 4 + 1];
            if (t.length() > 4) {

                int start = 0;
                int initLength = 4;
                for (int i = 0; i <= t.length() / 4; i++) {
                    if (initLength < t.length()) {
                        ts[i] = t.substring(start, initLength);
                        start = initLength;
                        initLength = initLength + 4;
                    } else {
                        initLength = t.length();
                        ts[i] = t.substring(start, initLength);
                        StringBuilder sb = new StringBuilder(ts[i]);

                        for (int j = 0; j < 4 - ts[i].length(); j++) {
                            sb.append(0);
                        }
                        ts[i] = sb.toString();
                    }

                }

            } else {
                ts = new String[]{t};
            }

        }
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < ts.length; i++) {
            result.append(encryption(ts[i], k));
        }
        return result.toString();


    }

    /**
     * Runs the encryption based on a key and a given plain-text.
     *
     * @param t arguments (containing the key and plain-text) 8bit
     * @param k key 32bit
     */
    public static String encryption(String t, String k) {

        /**
         * The key is the first argument.
         */
        String key = k;

        /**
         * The plain text is the second argument.
         * 8 bit plainText
         */
        String plainTextInput = t;

        // -------------------------------------------------------------------
        // DEFINE KEYS AND PLAINTEXT BASED ON GIVEN INFORMATION
        // EACH ROUND KEY IS A 4-BIT CONSECUTIVE SUB-KEY OF THE GIVEN KEY
        // EVERY ROUND INCREASES THE STARTING POSITION OF THE SUB-KEY BY 1
        // SEE P.76 OF STINSON FOR MORE INFORMATION
        // -------------------------------------------------------------------
        String[] firstRoundKey =
                {key.substring(0, 1), key.substring(1, 2), key.substring(2, 3),
                        key.substring(3, 4)};

        String[] secondRoundKey =
                {key.substring(1, 2), key.substring(2, 3), key.substring(3, 4),
                        key.substring(4, 5)};

        String[] thirdRoundKey =
                {key.substring(2, 3), key.substring(3, 4), key.substring(4, 5),
                        key.substring(5, 6)};

        String[] fourthRoundKey =
                {key.substring(3, 4), key.substring(4, 5), key.substring(5, 6),
                        key.substring(6, 7)};

        String[] fifthRoundKey =
                {key.substring(4, 5), key.substring(5, 6), key.substring(6, 7),
                        key.substring(7, 8)};

        String[] plainText =
                {plainTextInput.substring(0, 1), plainTextInput.substring(1, 2),
                        plainTextInput.substring(2, 3), plainTextInput.substring(3, 4)};

        /**
         * Holds all of the different round keys for easy access.
         */
        String[][] keys =
                {firstRoundKey, secondRoundKey, thirdRoundKey, fourthRoundKey,
                        fifthRoundKey};

        // -------------------------------------------------------------------
        // PRINTS OUT INITIALIZATION
        // -------------------------------------------------------------------
        System.out.println("Initializing program with key <" + key
                + "> and plain-text <" + plainTextInput + ">\n");

        for (String[] keyArray : keys) {
            System.out.print("Round " + currentRound + ": \tKey: "
                    + stringArrayToString(keyArray) + " \n\t\tBinary: ");

            System.out.println(hexadecimalToBinary(keyArray));
            currentRound++;
        }

        // -------------------------------------------------------------------
        // PRINTS OUT PRE-ROUND WORK
        // -------------------------------------------------------------------
        System.out.println("\n>>> Beginning pre-round work with plain-text <"
                + stringArrayToString(plainText) + "> and key <"
                + stringArrayToString(firstRoundKey) + ">");

        String originalPlainTextInBinary = hexadecimalToBinary(plainText);

        String key1InBinary = hexadecimalToBinary(firstRoundKey);

        String xorOriginalPTAndKey1 =
                performXOR(originalPlainTextInBinary, key1InBinary);

        String originalResultInHex = binaryToHexadecimal(xorOriginalPTAndKey1);

        System.out.println("\t" + originalPlainTextInBinary + " ("
                + binaryToHexadecimal(originalPlainTextInBinary) + ")\nXOR\t"
                + key1InBinary + " (" + binaryToHexadecimal(key1InBinary) + ")");

        System.out.println("------------------------");

        System.out.println("\t" + xorOriginalPTAndKey1 + " = "
                + originalResultInHex);

        /**
         * Reset the current round to 1 so that we can print information about
         * the rounds.
         */
        currentRound = 1;

        // -------------------------------------------------------------------
        // PRINTS OUT ROUNDS 1-3
        // -------------------------------------------------------------------
        String r1 = printRound(currentRound, originalResultInHex, keys);
        String r2 = printRound(currentRound, r1, keys);
        String r3 = printRound(currentRound, r2, keys);

        // -------------------------------------------------------------------
        // PRINTS OUT ROUND 4
        // -------------------------------------------------------------------
        System.out.println("\n>>> Beginning round " + currentRound
                + " with text <" + r3 + "> and key <"
                + stringArrayToString(keys[currentRound]) + ">");

        String resultAfterSBox = sBox(r3);
        String[] resultAfterSBoxAsArray = stringToStringArray(resultAfterSBox);
        String sBoxResultInBinary = hexadecimalToBinary(resultAfterSBoxAsArray);

        System.out.println("\nSbox:\t\t" + r3 + " --> " + resultAfterSBox
                + " = " + sBoxResultInBinary + "\n");

        System.out.println("\t" + sBoxResultInBinary + " ("
                + binaryToHexadecimal(sBoxResultInBinary) + ")" + "\nXOR\t"
                + hexadecimalToBinary(keys[currentRound]) + " ("
                + stringArrayToString(keys[currentRound]) + ")");

        System.out.println("------------------------");

        String xorSBoxAndRound =
                performXOR(
                        sBoxResultInBinary,
                        hexadecimalToBinary(keys[currentRound]));

        System.out.println("\t" + xorSBoxAndRound + " = "
                + binaryToHexadecimal(xorSBoxAndRound));

        // -------------------------------------------------------------------
        // PRINTS OUT CIPHER TEXT
        // -------------------------------------------------------------------
        System.out.print("\n>>> Cipher text: " + xorSBoxAndRound + " ("
                + binaryToHexadecimal(xorSBoxAndRound) + ")");
        return xorSBoxAndRound;
    } // END FUNCTION MAIN


    public static String decrytion(String c, String k) {
        /**
         * The key is the first argument.
         */
        String key = k;

        /**
         * The plain text is the second argument.
         * 8 bit plainText
         */
        String cypherTextInput = c;

        // -------------------------------------------------------------------
        // DEFINE KEYS AND PLAINTEXT BASED ON GIVEN INFORMATION
        // EACH ROUND KEY IS A 4-BIT CONSECUTIVE SUB-KEY OF THE GIVEN KEY
        // EVERY ROUND INCREASES THE STARTING POSITION OF THE SUB-KEY BY 1
        // SEE P.76 OF STINSON FOR MORE INFORMATION
        // -------------------------------------------------------------------
        String[] firstRoundKey =
                {key.substring(0, 1), key.substring(1, 2), key.substring(2, 3),
                        key.substring(3, 4)};

        String[] secondRoundKey =
                {key.substring(1, 2), key.substring(2, 3), key.substring(3, 4),
                        key.substring(4, 5)};

        String[] thirdRoundKey =
                {key.substring(2, 3), key.substring(3, 4), key.substring(4, 5),
                        key.substring(5, 6)};

        String[] fourthRoundKey =
                {key.substring(3, 4), key.substring(4, 5), key.substring(5, 6),
                        key.substring(6, 7)};

        String[] fifthRoundKey =
                {key.substring(4, 5), key.substring(5, 6), key.substring(6, 7),
                        key.substring(7, 8)};

        String[] cypherText =
                {cypherTextInput.substring(0, 1), cypherTextInput.substring(1, 2),
                        cypherTextInput.substring(2, 3), cypherTextInput.substring(3, 4)};

        /**
         * Holds all of the different round keys for easy access.
         */
        String[][] keys =
                {fifthRoundKey, fourthRoundKey, thirdRoundKey, secondRoundKey,
                        firstRoundKey};

        // -------------------------------------------------------------------
        // PRINTS OUT INITIALIZATION
        // -------------------------------------------------------------------
        System.out.println("Initializing program with key <" + key
                + "> and plain-text <" + cypherTextInput + ">\n");

        for (String[] keyArray : keys) {
            System.out.print("Round " + deRound + ": \tKey: "
                    + stringArrayToString(keyArray) + " \n\t\tBinary: ");

            System.out.println(hexadecimalToBinary(keyArray));
            deRound++;
        }

        // -------------------------------------------------------------------
        // PRINTS OUT PRE-ROUND WORK
        // -------------------------------------------------------------------

        System.out.println("\n>>> Beginning pre-round work with plain-text <"
                + stringArrayToString(cypherText) + "> and key <"
                + stringArrayToString(firstRoundKey) + ">");


        String originalCypherText = hexadecimalToBinary(cypherText);

        String key5InBinary = hexadecimalToBinary(fifthRoundKey);

        String v4 =
                performXOR(originalCypherText, key5InBinary);

        String v4Hex = binaryToHexadecimal(v4);

        String u4 = sBoxVerse(v4Hex);

        String[] u4Array = stringToStringArray(u4);

        String u4Hex = hexadecimalToBinary(u4Array);

        String w3 = performXOR(u4Hex, hexadecimalToBinary(fourthRoundKey));


        System.out.println("\t" + originalCypherText + " ("
                + binaryToHexadecimal(originalCypherText) + ")\nXOR\t"
                + key5InBinary + " (" + binaryToHexadecimal(key5InBinary) + ")");

        System.out.println("------------------------");

        System.out.println("\t" + v4 + " = "
                + v4Hex);

        /**
         * Reset the current round to 1 so that we can print information about
         * the rounds.
         */
        deRound = 2;

        // -------------------------------------------------------------------
        // PRINTS OUT ROUNDS 1-3
        // -------------------------------------------------------------------
        String w2 = printRoundVerse(deRound, w3, keys);
        String w1 = printRoundVerse(deRound, w2, keys);
        String w0 = printRoundVerse(deRound, w1, keys);

        // -------------------------------------------------------------------
        // PRINTS OUT ROUND 4
        // -------------------------------------------------------------------
//        System.out.println("\n>>> Beginning round " + currentRound
//                + " with text <" + w0 + "> and key <"
//                + stringArrayToString(keys[currentRound]) + ">");
//
//        String resultAfterSBox = sBox(w0);
//        String[] resultAfterSBoxAsArray = stringToStringArray(resultAfterSBox);
//        String sBoxResultInBinary = hexadecimalToBinary(resultAfterSBoxAsArray);
//
//        System.out.println("\nSbox:\t\t" + w0 + " --> " + resultAfterSBox
//                + " = " + sBoxResultInBinary + "\n");
//
//        System.out.println("\t" + sBoxResultInBinary + " ("
//                + binaryToHexadecimal(sBoxResultInBinary) + ")" + "\nXOR\t"
//                + hexadecimalToBinary(keys[currentRound]) + " ("
//                + stringArrayToString(keys[currentRound]) + ")");
//
//        System.out.println("------------------------");
//
//        String xorSBoxAndRound =
//                performXOR(
//                        sBoxResultInBinary,
//                        hexadecimalToBinary(keys[currentRound]));
//
//        System.out.println("\t" + xorSBoxAndRound + " = "
//                + binaryToHexadecimal(xorSBoxAndRound));
//
//        // -------------------------------------------------------------------
//        // PRINTS OUT CIPHER TEXT
//        // -------------------------------------------------------------------
//        System.out.print("\n>>> Cipher text: " + xorSBoxAndRound + " ("
//                + binaryToHexadecimal(xorSBoxAndRound) + ")");

        return binaryToHexadecimal(w0);
    }
    // ----------------------------------------------------------

    /**
     * Given the current round, the previous result as a hexadecimal string, and
     * the list of available keys to choose from, prints out the specific round
     * information and returns the resulting hexadecimal string.
     *
     * @param round               the round number
     * @param previousResultInHex the previous hexadecimal string result
     * @param keys                the array of keys to choose from
     * @return the resulting hexadecimal string
     */
    public static String printRound(
            int round,
            String previousResultInHex,
            String[][] keys) {
        // ---------------------------------------------------------------------
        // Takes the previous result in hexadecimal, sboxes it, runs it through
        // the permutation, and then performs an XOR with the current round key.
        // ---------------------------------------------------------------------
        String resultAfterSBox = sBox(previousResultInHex);

        String[] resultAfterSBoxAsArray = stringToStringArray(resultAfterSBox);

        String sBoxResultInBinary = hexadecimalToBinary(resultAfterSBoxAsArray);

        String sBoxBinaryPermutation =
                performBitPermutation(sBoxResultInBinary);

        String permutationInHex = binaryToHexadecimal(sBoxBinaryPermutation);

        String roundKey = hexadecimalToBinary(keys[round]);

        String xorOfRound = performXOR(sBoxBinaryPermutation, roundKey);

        // -------------------------------------------------------------------
        // Prints out all of the known information from the previous step,
        // increments the current round by 1, and returns the resulting
        // hexadecimal for future rounds to use.
        // -------------------------------------------------------------------
        System.out.println("\n>>> Beginning round " + round + " with text <"
                + previousResultInHex + "> and key <"
                + stringArrayToString(keys[round]) + ">");

        System.out.println("\nSbox:\t\t" + previousResultInHex + " --> "
                + resultAfterSBox + " = " + sBoxResultInBinary);

        System.out.println("Permutation:\t" + sBoxResultInBinary + " --> "
                + sBoxBinaryPermutation + " = " + permutationInHex + "\n");

        System.out.println("\t" + sBoxBinaryPermutation + " ("
                + binaryToHexadecimal(sBoxBinaryPermutation) + ")" + "\nXOR\t"
                + roundKey + " (" + binaryToHexadecimal(roundKey) + ")");

        System.out.println("------------------------");

        System.out.println("\t" + xorOfRound + " = "
                + binaryToHexadecimal(xorOfRound));

        currentRound++;

        return binaryToHexadecimal(xorOfRound);
    }

    public static String printRoundVerse(
            int round,
            String w,
            String[][] keys) {
        String vBin = performBitPermutation(w);

        String vHex = binaryToHexadecimal(vBin);

        String u = sBoxVerse(vHex);

        String[] uArray = stringToStringArray(u);

        String uBin = hexadecimalToBinary(uArray);

        String xorW = performXOR(uBin, hexadecimalToBinary(keys[round]));

        deRound++;

        return xorW;
    }

    // ----------------------------------------------------------

    /**
     * Performs and returns a bit permutation on a 16-bit long string. The bit
     * permutation is based on the original string's indexes as follows: 0, 4,
     * 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15th indexes.
     *
     * @param string given 16-bit long string
     * @return a permuted version of the original string
     */
    public static String performBitPermutation(String string) {
        String ret = "";

        if (string.length() != 16) {
            throw new Error("ERROR IN BIT PERMUTATION: STRING IS NOT LENGTH 16");
        } else {
            for (int i = 0; i < 4; i++) {
                ret +=
                        Character.toString(string.charAt(i))
                                + Character.toString(string.charAt(i + 4))
                                + Character.toString(string.charAt(i + 8))
                                + Character.toString(string.charAt(i + 12));
            }
        }
        return ret;
    }


    // ----------------------------------------------------------

    /**
     * Given a hexadecimal string, performs a substitution on each string as
     * given in Stinson's text and returns the substitution. IE: this runs the
     * string through the "sbox".
     *
     * @param hexadecimalString a hexadecimal string
     * @return the hexadecimal string after sbox-ing
     */
    public static String sBox(String hexadecimalString) {
        String ret = "";

        for (int i = 0; i < 4; i++) {
            switch (hexadecimalString.charAt(i)) {
                case '0':
                    ret += "E";
                    break;

                case '1':
                    ret += "4";
                    break;

                case '2':
                    ret += "D";
                    break;

                case '3':
                    ret += "1";
                    break;

                case '4':
                    ret += "2";
                    break;

                case '5':
                    ret += "F";
                    break;

                case '6':
                    ret += "B";
                    break;

                case '7':
                    ret += "8";
                    break;

                case '8':
                    ret += "3";
                    break;

                case '9':
                    ret += "A";
                    break;

                case 'A':
                    ret += "6";
                    break;

                case 'B':
                    ret += "C";
                    break;

                case 'C':
                    ret += "5";
                    break;

                case 'D':
                    ret += "9";
                    break;

                case 'E':
                    ret += "0";
                    break;

                case 'F':
                    ret += "7";
                    break;
            }

        }

        return ret;
    }

    public static String sBoxVerse(String hexadecimalString) {
        String ret = "";

        for (int i = 0; i < 4; i++) {
            switch (hexadecimalString.charAt(i)) {
                case '0':
                    ret += "E";
                    break;

                case '1':
                    ret += "3";
                    break;

                case '2':
                    ret += "4";
                    break;

                case '3':
                    ret += "8";
                    break;

                case '4':
                    ret += "1";
                    break;

                case '5':
                    ret += "C";
                    break;

                case '6':
                    ret += "A";
                    break;

                case '7':
                    ret += "F";
                    break;

                case '8':
                    ret += "7";
                    break;

                case '9':
                    ret += "D";
                    break;

                case 'A':
                    ret += "9";
                    break;

                case 'B':
                    ret += "6";
                    break;

                case 'C':
                    ret += "B";
                    break;

                case 'D':
                    ret += "2";
                    break;

                case 'E':
                    ret += "0";
                    break;

                case 'F':
                    ret += "5";
                    break;
            }

        }

        return ret;
    }


    // ----------------------------------------------------------

    /**
     * Performs and returns a string-based XOR on two strings consisting of 1s
     * and 0s.
     *
     * @param string1 a string consisting of 1s and 0s
     * @param string2 a string consisting of 1s and 0s
     * @return the XOR of two strings consisting of 1s and 0s
     */
    public static String performXOR(String string1, String string2) {
        String ret = "";

        for (int i = 0; i < 16; i++)
            ret += string1.charAt(i) ^ string2.charAt(i);

        return ret;
    }


    // ----------------------------------------------------------

    /**
     * Given a string that is in binary (consists only of 0s and 1s), converts
     * and returns the string in hexadecimal format.
     *
     * @param binaryString a binary string
     * @return the hexadecimal version of the binary string
     */
    public static String binaryToHexadecimal(String binaryString) {
        String ret = "";
        String hexadecimalString =
                new BigInteger(binaryString, 2).toString(16).toUpperCase();
        int length = hexadecimalString.length();

        while (length < 4) {
            ret += "0";
            length++;
        }
        ret += hexadecimalString;
        return ret;
    }


    // ----------------------------------------------------------

    /**
     * Given an array of hexadecimal strings, loops through the array, and
     * returns a String that represents the array of hexadecimal strings in
     * binary. In this particular implementation, each element in the array
     * represents one hexadecimal character.
     *
     * @param hexStringArray an array of hexadecimal strings
     * @return a String representation of the hexadecimal string array in binary
     */
    public static String hexadecimalToBinary(String[] hexStringArray) {
        String ret = "";

        for (String s : hexStringArray)
            ret += hexToBin(s);

        return ret;
    }


    // ----------------------------------------------------------

    /**
     * Given a string in hexadecimal, converts and returns a string
     * representation of the hexadecimal in binary. In this particular
     * implementation, the string must be a single hexadecimal character, such
     * as "E". This function pads the beginning of the binary representation
     * with 0s to ensure it is always of 4-bitl ength.
     *
     * @param hexadecimalString a hexadecimal string
     * @return string representation of the hexadecimal string in binary
     */
    public static String hexToBin(String hexadecimalString) {
        String ret = "";
        String binaryString = new BigInteger(hexadecimalString, 16).toString(2);
        int length = binaryString.length();

        while (length < 4) {
            ret += "0";
            length++;
        }

        ret += binaryString;
        return ret;
    }


    // ----------------------------------------------------------

    /**
     * Given an array of strings, returns a representation of the entire array
     * of strings as a single string.
     *
     * @param array an array of strings
     * @return a string representation of the array of strings
     */
    public static String stringArrayToString(String[] array) {
        String ret = "";

        for (String s : array)
            ret += s;

        return ret;
    }


    // ----------------------------------------------------------

    /**
     * Given a string, returns a representation of the string as an array. For
     * example, "Eric" would have 0=>E, 1=>r, 2=>i, 3=>c.
     *
     * @param string a string
     * @return array of strings representing the original string
     */
    public static String[] stringToStringArray(String string) {
        String[] ret = new String[string.length()];

        for (int i = 0; i < string.length(); i++)
            ret[i] = Character.toString(string.charAt(i));

        return ret;
    }
}