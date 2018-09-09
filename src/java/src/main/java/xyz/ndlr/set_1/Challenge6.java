package xyz.ndlr.set_1;

import xyz.ndlr.utill.ConvertionHelper;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.PriorityQueue;
import java.util.Scanner;

public class Challenge6 {
    private Challenge4 challenge4;
    private Challenge5 challenge5;
    private ConvertionHelper convertionHelper;


    public Challenge6(Challenge4 challenge4, Challenge5 challenge5, ConvertionHelper
            convertionHelper) {
        this.challenge4 = challenge4;
        this.challenge5 = challenge5;
        this.convertionHelper = convertionHelper;
    }

    public byte[] breakRepeatingKeyXOR(byte[] base64Xored) {
        PriorityQueue<KeyDistance> queue = new PriorityQueue<>(KeyDistance::compareTo);

        byte[] xored = this.decodeBase64(base64Xored);

        for (int keySize = 2; keySize <= 42; keySize++) {
            byte[] first = Arrays.copyOfRange(xored, 0, keySize);
            byte[] second = Arrays.copyOfRange(xored, keySize, keySize * 2);
            byte[] third = Arrays.copyOfRange(xored, keySize * 2, keySize * 3);
            byte[] fourth = Arrays.copyOfRange(xored, keySize * 3, keySize * 4);

            int editDistance = computeHammingDistance(first, second);
            float normalizedEditDistance = ((float) editDistance) / (float) keySize;

            int editDistance2 = computeHammingDistance(third, fourth);
            float normalizedEditDistance2 = ((float) editDistance2) / (float) keySize;

            float averageNormalizedEditDistance = (normalizedEditDistance +
                    normalizedEditDistance2) / 2;

            queue.add(new KeyDistance(averageNormalizedEditDistance, keySize));
        }

        for (int i = 0; i < 3; i++) {
            KeyDistance keyDistance = queue.poll();
            int keySize = keyDistance.getKeySize();
            byte[][] xoredSplit =
                    new byte[xored.length / keySize][keySize];

            for (int j = 0; j < xoredSplit.length; j++) {
                int from = j * keySize;
                int to = from + keySize;

                xoredSplit[j] = Arrays.copyOfRange(xored, from, to);
            }

            byte[][] transposedXoredSplit = transpose(xoredSplit);

            XORComparison[] comparisons =
                    challenge4.getAllBestSingleCharacterXOR(transposedXoredSplit);

            byte[] key = new byte[comparisons.length];
            for (int j = 0; j < comparisons.length; j++)
                key[j] = (byte) comparisons[j].getCharacter();

            byte[] decrypted = challenge5.repeatingKeyXOR(xored, key);
        }

        return new byte[0];
    }

    private byte[][] transpose(byte[][] matrix) {
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
        byte xor = (byte) (character1 ^ character2);
        byte distance = 0;

        while (xor != 0) {
            distance += xor & 1;
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
