package xyz.ndlr.set_1;

import xyz.ndlr.utill.ConvertionHelper;

public class Challenge6 {
    private ConvertionHelper convertionHelper;

    public Challenge6(ConvertionHelper convertionHelper) {
        this.convertionHelper = convertionHelper;
    }

    public byte[] breakRepeatingKeyXOR() {
        return new byte[0];
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
}
