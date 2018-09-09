package xyz.ndlr.set_1;

import xyz.ndlr.utill.ConvertionHelper;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.PriorityQueue;
import java.util.Scanner;

public class Challenge6 {
    public static final int MIN_KEY_LENGTH = 2;
    public static final int MAX_KEY_LENGTH = 40;
    public static final int BEST_GUESSES_TO_CHECK = 10;

    private Challenge4 challenge4;
    private Challenge5 challenge5;
    private ConvertionHelper convertionHelper;


    public Challenge6(Challenge4 challenge4, Challenge5 challenge5, ConvertionHelper
            convertionHelper) {
        this.challenge4 = challenge4;
        this.challenge5 = challenge5;
        this.convertionHelper = convertionHelper;
    }

    public byte[][] breakRepeatingKeyXOR(byte[] base64Xored) {
        byte[] xored = this.decodeBase64(base64Xored);
        PriorityQueue<KeyDistance> queue = findBestGuesses(xored,
                MIN_KEY_LENGTH, MAX_KEY_LENGTH);

        byte[][] decrypted = new byte[BEST_GUESSES_TO_CHECK][xored.length];
        for (int i = 0; i < BEST_GUESSES_TO_CHECK; i++) {
            KeyDistance keyDistance = queue.poll();
            int keySize = keyDistance.getKeySize();

            byte[][] xoredSplit = this.splitIntoBlocks(xored, keySize);
            byte[][] transposedXoredSplit = transpose(xoredSplit);

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

    public byte[][] splitIntoBlocks(byte[] bytes, int size) {
        byte[][] blocks = new byte[(bytes.length + size - 1) / size][size];

        for (int i = 0; i < blocks.length; i++) {
            int from = i * size;
            int to = from + size;

            blocks[i] = Arrays.copyOfRange(bytes, from, to);
        }

        return blocks;
    }

    public byte[][] transpose(byte[][] matrix) {
        byte[][] transposed = new byte[matrix[0].length][matrix.length];
        for (int i = 0; i < matrix.length; i++) {
            for (int j = 0; j < matrix[0].length; j++) {
                transposed[j][i] = matrix[i][j];
            }
        }

        return transposed;
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
        StringBuilder builder = new StringBuilder();

        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource(fileName).getFile());

        try (Scanner scanner = new Scanner(file)) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                builder.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return convertionHelper.stringToBytes(builder.toString());
    }
}
