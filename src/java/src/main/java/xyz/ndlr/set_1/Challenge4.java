package xyz.ndlr.set_1;

import xyz.ndlr.utill.ConvertionHelper;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;

public class Challenge4 {
    private Challenge3 challenge3;
    private ConvertionHelper convertionHelper;

    public Challenge4(Challenge3 challenge3, ConvertionHelper convertionHelper) {
        this.challenge3 = challenge3;
        this.convertionHelper = convertionHelper;
    }

    public XORComparison detectSingleCharacterXOR(byte[][] strings) {
        byte[] alphabet = new byte[255];
        for (int i = 1; i < 255; i++)
            alphabet[i - 1] = (byte) i;

        XORComparison bestComparison = XORComparison.DEFAULT;
        for (byte[] string : strings) {
            XORComparison currentComparison = this.challenge3
                    .singleByteXORCipher(string, alphabet);

            if (currentComparison.isBetterThan(bestComparison)) {
                bestComparison = currentComparison;
            }
        }

        return bestComparison;
    }

    public byte[][] getFileContents(String fileName) {
        List<String> lines = new ArrayList<>();

        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource(fileName).getFile());

        try (Scanner scanner = new Scanner(file)) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                lines.add(line);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

        List<byte[]> byteLines = lines.stream()
                .map(convertionHelper::hexToBytes)
                .collect(Collectors.toList());

        byte[][] bytesArray = new byte[lines.size()][byteLines.get(0).length];

        return byteLines.toArray(bytesArray);
    }
}
