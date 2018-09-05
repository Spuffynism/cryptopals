package xyz.ndlr.set_1;

import java.util.Base64;

public class Challenge1 {
    public byte[] convertHexToBase64(byte[] characters) {
        Base64.Encoder encoder = Base64.getEncoder();

        return encoder.encode(characters);
    }
}
