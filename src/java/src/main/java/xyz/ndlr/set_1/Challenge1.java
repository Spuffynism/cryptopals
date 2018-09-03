package xyz.ndlr.set_1;

import xyz.ndlr.utill.ConvertHelper;

import java.util.Base64;

public class Challenge1 {
    private ConvertHelper convertHelper;

    public Challenge1(ConvertHelper convertHelper) {
        this.convertHelper = convertHelper;
    }

    public byte[] convertHexToBase64(byte[] characters) {
        Base64.Encoder encoder = Base64.getEncoder();

        return encoder.encode(characters);
    }
}
