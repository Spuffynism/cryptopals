package xyz.ndlr.set_1;

import java.util.Arrays;

public class Challenge3 {
    public static final String ENGLISH_CHARACTERS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ:'?!,- /\\\".@\n";

    public XORComparison singleByteXORCipher(byte[] xoredMessage, byte[] alphabet) {
        byte[] bestXoredWithChar = new byte[xoredMessage.length];
        int bestScore = -1;
        char bestCharacter = (char) alphabet[0];
        for (byte character : alphabet) {
            byte[] currentXored = xorWithChar(xoredMessage, (char) character);

            int currentScore = calculateEnglishResemblanceScore(
                    Arrays.copyOf(currentXored, currentXored.length));

            if (currentScore > bestScore) {
                bestScore = currentScore;
                bestXoredWithChar = Arrays.copyOf(currentXored, currentXored.length);
                bestCharacter = (char) character;

                // if the score is equal to the string's length, we must have found human text
                if (currentScore == xoredMessage.length) {
                    break;
                }
            }
        }

        return new XORComparison(bestXoredWithChar, bestScore, bestCharacter);
    }

    private byte[] xorWithChar(byte[] bytes, char xor) {
        byte[] xoredWithChar = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++)
            xoredWithChar[i] = (byte) (bytes[i] ^ xor);

        return xoredWithChar;
    }

    // TODO: Change this for a markov chain test
    private int calculateEnglishResemblanceScore(byte[] bytes) {
        byte[] alphabet = ENGLISH_CHARACTERS.getBytes();

        Arrays.sort(alphabet); // O(n log(n))
        Arrays.sort(bytes); // O(n log(n))

        int resemblance = 0;
        // O(n)
        for (int i = 0, j = 0; i < bytes.length && j < alphabet.length; ) {
            if (bytes[i] == alphabet[j]) {
                resemblance++;
                i++;
            } else if (bytes[i] < alphabet[j]) {
                i++;
            } else {
                j++;
            }
        }

        /*
        // Checks that the content has spaces in it
        byte space = (byte) ' ';

        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] == space)
                return resemblance;
        }*/

        return resemblance;
    }
}
