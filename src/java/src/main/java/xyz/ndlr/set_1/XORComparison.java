package xyz.ndlr.set_1;

import java.util.Arrays;

public class XORComparison {
    private byte[] xoredWithChar;
    private double humanLikenessScore;
    private char character;

    public static XORComparison DEFAULT = new XORComparison(new byte[0], 0, (char) 0);

    XORComparison(byte[] xoredWithChar, double humanLikenessScore, char character) {
        this.xoredWithChar = xoredWithChar;
        this.humanLikenessScore = humanLikenessScore;
        this.character = character;
    }

    public byte[] getXoredWithChar() {
        return xoredWithChar;
    }

    public double getHumanLikenessScore() {
        return humanLikenessScore;
    }

    public char getCharacter() {
        return character;
    }

    public boolean isBetterThan(XORComparison other) {
        return this.humanLikenessScore > other.humanLikenessScore;
    }

    public static byte[] buildKey(XORComparison[] comparisons) {
        byte[] key = new byte[comparisons.length];
        for (int j = 0; j < comparisons.length; j++)
            key[j] = (byte) comparisons[j].getCharacter();

        return key;
    }

    @Override
    public String toString() {
        return "XORComparison{" +
                "xoredWithChar=" + Arrays.toString(xoredWithChar) +
                ", humanLikenessScore=" + humanLikenessScore +
                ", character=" + character +
                '}';
    }
}
