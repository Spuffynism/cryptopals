package xyz.ndlr.set_1;

public class Challenge5 {
    public byte[] repeatingKeyXOR(byte[] message, byte[] key) {
        byte[] xoredMessage = new byte[message.length];

        for (int i = 0; i < message.length; i++) {
            xoredMessage[i] = (byte) (message[i] ^ key[i % key.length]);
        }

        return xoredMessage;
    }
}
