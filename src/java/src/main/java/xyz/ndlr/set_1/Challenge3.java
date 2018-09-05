package xyz.ndlr.set_1;

import xyz.ndlr.utill.ConvertHelper;

import java.util.Arrays;

public class Challenge3 {
    private static final String ENGLISH_CHARACTERS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ:'?! \".@";

    public byte[] singleByteXORCipher(byte[] xoredMessage) {
        byte[] alphabet = ENGLISH_CHARACTERS.getBytes();

        int bestScore = -1;
        byte[] bestXoredWithChar = new byte[xoredMessage.length];
        for (byte character : alphabet) {
            byte[] currentXored = xorWithChar(xoredMessage, (char) character);

            int currentScore = calculateEnglishResemblanceScore(
                    Arrays.copyOf(currentXored, currentXored.length),
                    Arrays.copyOf(alphabet, alphabet.length));

            if (currentScore > bestScore) {
                bestScore = currentScore;
                bestXoredWithChar = Arrays.copyOf(currentXored, currentXored.length);

                // if the score is equal to the string's length, we must have found human text
                if (currentScore == xoredMessage.length) {
                    break;
                }
            }
        }

        return bestXoredWithChar;
    }

    private byte[] xorWithChar(byte[] bytes, char xor) {
        byte[] xoredWithChar = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++)
            xoredWithChar[i] = (byte) (bytes[i] ^ xor);

        return xoredWithChar;
    }

    private int calculateEnglishResemblanceScore(byte[] bytes, byte[] alphabet) {
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

        return resemblance;
    }
}
