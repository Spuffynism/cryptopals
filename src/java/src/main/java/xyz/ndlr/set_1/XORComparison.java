package xyz.ndlr.set_1;

import java.util.Arrays;

public class XORComparison {
    private byte[] xoredWithChar;
    private int humanLikenessScore;
    private char character;

    public static XORComparison DEFAULT = new XORComparison(new byte[0], 0, (char) 0);

    XORComparison(byte[] xoredWithChar, int humanLikenessScore, char character) {
        this.xoredWithChar = xoredWithChar;
        this.humanLikenessScore = humanLikenessScore;
        this.character = character;
    }

    public byte[] getXoredWithChar() {
        return xoredWithChar;
    }

    public int getHumanLikenessScore() {
        return humanLikenessScore;
    }

    public char getCharacter() {
        return character;
    }

    public boolean isBetterThan(XORComparison other) {
        return this.humanLikenessScore > other.humanLikenessScore;
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
