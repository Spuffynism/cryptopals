package xyz.ndlr;

import org.junit.Assert;
import org.junit.Test;
import xyz.ndlr.set_1.Challenge1;
import xyz.ndlr.set_1.Challenge2;
import xyz.ndlr.set_1.Challenge3;
import xyz.ndlr.utill.ConvertHelper;

public class Set1Test {
    @Test
    public void challenge1() {
        ConvertHelper convertHelper = new ConvertHelper();
        Challenge1 challenge1 = new Challenge1();

        String input =
                "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        String expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        byte[] inputBytes = convertHelper.hexToBytes(input);
        byte[] expectedBytes = expected.getBytes();

        byte[] actualBytes = challenge1.convertHexToBase64(inputBytes);

        Assert.assertArrayEquals(expectedBytes, actualBytes);
    }

    @Test
    public void challenge2() {
        ConvertHelper convertHelper = new ConvertHelper();
        Challenge2 challenge2 = new Challenge2();

        String actual = "1c0111001f010100061a024b53535009181c";
        String xorKey = "686974207468652062756c6c277320657965";
        String expected = "746865206b696420646f6e277420706c6179";

        byte[] result = challenge2.fixedXOR(convertHelper.hexToBytes(actual), convertHelper
                .hexToBytes(xorKey));
        byte[] expectedBytes = convertHelper.hexToBytes(expected);
        Assert.assertArrayEquals(expectedBytes, result);
    }

    @Test
    public void challenge3() {
        ConvertHelper convertHelper = new ConvertHelper();
        Challenge3 challenge3 = new Challenge3();

        String actual = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        String expected = "Cooking MC's like a pound of bacon";

        byte[] actualBytes = convertHelper.hexToBytes(actual);
        byte[] result = challenge3.singleByteXORCipher(actualBytes);

        Assert.assertArrayEquals(expected.getBytes(), result);
    }
}
