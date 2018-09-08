package xyz.ndlr;

import org.junit.Assert;
import org.junit.Test;
import xyz.ndlr.set_1.*;
import xyz.ndlr.utill.ConvertionHelper;

public class Set1Test {
    @Test
    public void challenge1() {
        ConvertionHelper convertionHelper = new ConvertionHelper();
        Challenge1 challenge1 = new Challenge1();

        String input =
                "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        String expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        byte[] inputBytes = convertionHelper.hexToBytes(input);
        byte[] expectedBytes = expected.getBytes();

        byte[] actualBytes = challenge1.convertHexToBase64(inputBytes);

        Assert.assertArrayEquals(expectedBytes, actualBytes);
    }

    @Test
    public void challenge2() {
        ConvertionHelper convertionHelper = new ConvertionHelper();
        Challenge2 challenge2 = new Challenge2();

        String actual = "1c0111001f010100061a024b53535009181c";
        String xorKey = "686974207468652062756c6c277320657965";
        String expected = "746865206b696420646f6e277420706c6179";

        byte[] result = challenge2.fixedXOR(convertionHelper.hexToBytes(actual), convertionHelper
                .hexToBytes(xorKey));
        byte[] expectedBytes = convertionHelper.hexToBytes(expected);
        Assert.assertArrayEquals(expectedBytes, result);
    }

    @Test
    public void challenge3() {
        ConvertionHelper convertionHelper = new ConvertionHelper();
        Challenge3 challenge3 = new Challenge3();

        String actual = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        String expected = "Cooking MC's like a pound of bacon";

        byte[] actualBytes = convertionHelper.hexToBytes(actual);
        XORComparison result = challenge3.singleByteXORCipher(actualBytes,
                Challenge3.ENGLISH_CHARACTERS.getBytes());

        Assert.assertArrayEquals(expected.getBytes(), result.getXoredWithChar());
    }

    @Test
    public void challenge4() {
        ConvertionHelper convertionHelper = new ConvertionHelper();
        Challenge4 challenge4 = new Challenge4(new Challenge3(), convertionHelper);
        byte[][] lines = challenge4.getFileContents("challenge_data/4.txt");

        XORComparison actual = challenge4.detectSingleCharacterXOR(lines);
        String expected = "Now that the party is jumping\n";

        byte[] actualXoredWithChar = actual.getXoredWithChar();
        Assert.assertArrayEquals(convertionHelper.stringToBytes(expected), actualXoredWithChar);
    }

    @Test
    public void challenge5() {
        ConvertionHelper convertionHelper = new ConvertionHelper();
        Challenge5 challenge5 = new Challenge5();

        String actual = "Burning 'em, if you ain't quick and nimble\n" +
                "I go crazy when I hear a cymbal";
        String actualKey = "ICE";
        String expected =
                "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\n" +
                        "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

        byte[] actualBytes = convertionHelper.stringToBytes(actual);
        byte[] actualKeyBytes = convertionHelper.stringToBytes(actualKey);
        byte[] expectedBytes = convertionHelper.hexToBytes(expected);

        Assert.assertArrayEquals(expectedBytes, challenge5.repeatingKeyXOR(actualBytes,
                actualKeyBytes));
    }

    @Test
    public void challenge6HammingDistance() {
        ConvertionHelper convertionHelper = new ConvertionHelper();
        Challenge6 challenge6 = new Challenge6(convertionHelper);

        int expectedDistance = 37;
        byte[] string1 = convertionHelper.stringToBytes("this is a test");
        byte[] string2 = convertionHelper.stringToBytes("wokka wokka!!!");

        int actualDistance = challenge6.computeHammingDistance(string1, string2);

        Assert.assertEquals(expectedDistance, actualDistance);
    }

    @Test
    public void challenge6() {
        ConvertionHelper convertionHelper = new ConvertionHelper();
        Challenge6 challenge6 = new Challenge6(convertionHelper);


    }
}
