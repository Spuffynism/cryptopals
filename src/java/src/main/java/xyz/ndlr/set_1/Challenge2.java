package xyz.ndlr.set_1;

public class Challenge2 {
    public byte[] fixedXOR(byte[] characters, byte[] xorKey) {
        byte[] xoredCharacters = new byte[characters.length];

        for (int i = 0; i < characters.length; i++) {
            xoredCharacters[i] = (byte) (characters[i] ^ xorKey[i]);
        }

        return xoredCharacters;
    }
}
