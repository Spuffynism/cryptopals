package xyz.ndlr.set_1;

import xyz.ndlr.utill.ArrayUtil;
import xyz.ndlr.utill.FileUtil;

import java.util.Arrays;
import java.util.Base64;
import java.util.PriorityQueue;

public class Challenge6 {
    public static final int MIN_KEY_LENGTH = 2;
    public static final int MAX_KEY_LENGTH = 40;
    public static final int BEST_GUESSES_TO_CHECK = 10;

    private Challenge4 challenge4;
    private Challenge5 challenge5;
    private ArrayUtil arrayUtil;
    private FileUtil fileUtil;


    public Challenge6(Challenge4 challenge4, Challenge5 challenge5,
                      ArrayUtil arrayUtil,
                      FileUtil fileUtil) {
        this.challenge4 = challenge4;
        this.challenge5 = challenge5;
        this.arrayUtil = arrayUtil;
        this.fileUtil = fileUtil;
    }

    public byte[][] breakRepeatingKeyXOR(byte[] base64Xored) {
        byte[] xored = this.decodeBase64(base64Xored);
        PriorityQueue<KeyDistance> queue = findBestGuesses(xored,
                MIN_KEY_LENGTH, MAX_KEY_LENGTH);

        byte[][] decrypted = new byte[BEST_GUESSES_TO_CHECK][xored.length];
        for (int i = 0; i < BEST_GUESSES_TO_CHECK; i++) {
            KeyDistance keyDistance = queue.poll();
            int keySize = keyDistance.getKeySize();

            byte[][] xoredSplit = arrayUtil.splitIntoBlocks(xored, keySize);
            byte[][] transposedXoredSplit = arrayUtil.transpose(xoredSplit);

            XORComparison[] comparisons = challenge4.getAllBestSingleCharacterXOR
                    (transposedXoredSplit);

            byte[] key = new byte[comparisons.length];
            for (int j = 0; j < comparisons.length; j++)
                key[j] = (byte) comparisons[j].getCharacter();

            decrypted[i] = challenge5.repeatingKeyXOR(xored, key);
        }

        return decrypted;
    }

    public PriorityQueue<KeyDistance> findBestGuesses(byte[] bytes,
                                                      int minKeyLength,
                                                      int maxKeyLength) {
        PriorityQueue<KeyDistance> bestGuesses = new PriorityQueue<>(KeyDistance::compareTo);

        for (int keySize = minKeyLength; keySize <= maxKeyLength; keySize++) {
            byte[] first = Arrays.copyOfRange(bytes, 0, keySize);
            byte[] second = Arrays.copyOfRange(bytes, keySize, keySize * 2);
            byte[] third = Arrays.copyOfRange(bytes, keySize * 2, keySize * 3);
            byte[] fourth = Arrays.copyOfRange(bytes, keySize * 3, keySize * 4);

            double editDistance = computeHammingDistance(first, second);
            double editDistance2 = computeHammingDistance(third, fourth);

            double averageNormalizedEditDistance =
                    (editDistance + editDistance2) / 2 / keySize;

            bestGuesses.add(new KeyDistance(averageNormalizedEditDistance, keySize));
        }

        return bestGuesses;
    }

    private byte[] decodeBase64(byte[] base64Encoded) {
        Base64.Decoder decoder = Base64.getDecoder();

        return decoder.decode(base64Encoded);
    }

    public int computeHammingDistance(byte[] string1, byte[] string2) {
        int distance = 0;

        for (int i = 0; i < string1.length && i < string2.length; i++) {
            distance += computeHammingDistance(string1[i], string2[i]);
        }

        return distance;
    }

    private int computeHammingDistance(byte character1, byte character2) {
        int xor = ((byte) (character1 ^ character2)) & 0xFF;
        int distance = 0;

        while (xor != 0) {
            distance += ((byte) xor) & 1;
            xor >>= 1;
        }

        return distance;
    }

    public byte[] getFileContents(String fileName) {
        return fileUtil.getResource(fileName);
    }
}
