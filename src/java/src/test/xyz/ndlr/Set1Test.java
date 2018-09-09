package xyz.ndlr;

import org.junit.Assert;
import org.junit.Test;
import xyz.ndlr.set_1.*;
import xyz.ndlr.utill.ConvertionHelper;

import java.util.Arrays;
import java.util.Base64;
import java.util.PriorityQueue;
import java.util.stream.Stream;

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
    public void challenge6ComputeHammingDistance() {
        ChallengeFactory challengeFactory = new ChallengeFactory();
        Challenge6 challenge6 = challengeFactory.getChallenge6();
        ConvertionHelper convertionHelper = new ConvertionHelper();

        int expectedDistance = 37;
        byte[] string1 = convertionHelper.stringToBytes("this is a test");
        byte[] string2 = convertionHelper.stringToBytes("wokka wokka!!!");

        int actualDistance = challenge6.computeHammingDistance(string1, string2);

        Assert.assertEquals(expectedDistance, actualDistance);
    }

    @Test
    public void challenge6Transpose() {
        ChallengeFactory challengeFactory = new ChallengeFactory();
        Challenge6 challenge6 = challengeFactory.getChallenge6();

        byte[][] matrix = new byte[][]{
                {1, 2, 3},
                {4, 5, 6},
                {7, 8, 9}
        };

        byte[][] expected = new byte[][]{
                {1, 4, 7},
                {2, 5, 8},
                {3, 6, 9}
        };

        Assert.assertArrayEquals(expected, challenge6.transpose(matrix));
    }

    @Test
    public void challenge6SplitIntoBlocksEven() {
        ChallengeFactory challengeFactory = new ChallengeFactory();
        Challenge6 challenge6 = challengeFactory.getChallenge6();

        byte[] bytes = new byte[]{2, 2, 3, 3, 4, 4};
        int blockSize = 2;
        byte[][] expected = new byte[][]{
                {2, 2},
                {3, 3},
                {4, 4}
        };

        Assert.assertArrayEquals(expected, challenge6.splitIntoBlocks(bytes, blockSize));
    }

    @Test
    public void challenge6SplitIntoBlocksOdd() {
        ChallengeFactory challengeFactory = new ChallengeFactory();
        Challenge6 challenge6 = challengeFactory.getChallenge6();

        byte[] bytes = new byte[]{2, 2, 3, 3, 4, 4, 5};
        int blockSize = 2;
        byte[][] expected = new byte[][]{
                {2, 2},
                {3, 3},
                {4, 4},
                {5, 0}
        };

        Assert.assertArrayEquals(expected, challenge6.splitIntoBlocks(bytes, blockSize));
    }

    @Test
    public void findBestGuessesEasy() {
        ChallengeFactory challengeFactory = new ChallengeFactory();
        Challenge6 challenge6 = challengeFactory.getChallenge6();

        byte[] bytes = new byte[40 * 4];
        byte[] choices = new byte[]{0b111, 0b101};
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = choices[i % choices.length];
        }

        PriorityQueue<KeyDistance> bestGuesses = challenge6.findBestGuesses(bytes,
                Challenge6.MIN_KEY_LENGTH, Challenge6.MAX_KEY_LENGTH);
        KeyDistance bestGuess = bestGuesses.poll();
        KeyDistance secondBestGuess = bestGuesses.poll();
        KeyDistance thirdBestGuess = bestGuesses.poll();

        Assert.assertEquals(0, bestGuess.getDistance(), 0d);
        Assert.assertEquals(2, bestGuess.getKeySize());
        Assert.assertEquals(0, secondBestGuess.getDistance(), 0d);
        Assert.assertEquals(6, secondBestGuess.getKeySize());
        Assert.assertEquals(0, thirdBestGuess.getDistance(), 0d);
        Assert.assertEquals(10, thirdBestGuess.getKeySize());
    }

    @Test
    public void findBestGuessesXored() {
        ChallengeFactory challengeFactory = new ChallengeFactory();
        Challenge5 challenge5 = challengeFactory.getChallenge5();
        Challenge6 challenge6 = challengeFactory.getChallenge6();

        byte[] bytes = new byte[40 * 4];
        byte[] xor = new byte[]{0b111, 0b101, 0b101};
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) i;
        }

        byte[] xored = challenge5.repeatingKeyXOR(bytes, xor);
        PriorityQueue<KeyDistance> bestGuesses = challenge6.findBestGuesses(xored,
                1, 32);

        KeyDistance bestGuess = bestGuesses.poll();
        KeyDistance secondBestGuess = bestGuesses.poll();
        KeyDistance thirdBestGuess = bestGuesses.poll();

        Assert.assertEquals(0.25, bestGuess.getDistance(), 0d);
        Assert.assertEquals(2, bestGuess.getKeySize());
        Assert.assertEquals(1.67, secondBestGuess.getDistance(), 0.01d);
        Assert.assertEquals(32, secondBestGuess.getKeySize());
        Assert.assertEquals(1.68, thirdBestGuess.getDistance(), 0.01d);
        Assert.assertEquals(8, thirdBestGuess.getKeySize());
    }

    @Test
    public void findBestGuessesXoredShort() {
        ChallengeFactory challengeFactory = new ChallengeFactory();
        Challenge5 challenge5 = challengeFactory.getChallenge5();
        Challenge6 challenge6 = challengeFactory.getChallenge6();

        byte item = 0b111;
        byte xor = 0b101;

        int maxKeyLength = 2;
        byte[] bytes = new byte[maxKeyLength * 4];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = item;
        }

        byte[] xored = challenge5.repeatingKeyXOR(bytes, new byte[]{xor});
        PriorityQueue<KeyDistance> bestGuesses = challenge6.findBestGuesses(xored,
                1, maxKeyLength);

        KeyDistance bestGuess = bestGuesses.poll();
        KeyDistance secondBestGuess = bestGuesses.poll();

        Assert.assertEquals(0, bestGuess.getDistance(), 0d);
        Assert.assertEquals(1, bestGuess.getKeySize());
        Assert.assertEquals(0, secondBestGuess.getDistance(), 0d);
        Assert.assertEquals(2, secondBestGuess.getKeySize());
    }

    @Test
    public void challenge6() {
        ChallengeFactory challengeFactory = new ChallengeFactory();
        Challenge6 challenge6 = challengeFactory.getChallenge6();
        ConvertionHelper convertionHelper = new ConvertionHelper();

        byte[] solution = challenge6.getFileContents("challenge_data/6_solution.txt");
        byte[] base64Xored = challenge6.getFileContents("challenge_data/6.txt");

        byte[][] guesses = challenge6.breakRepeatingKeyXOR(base64Xored);

        Base64.Decoder decoder = Base64.getDecoder();
        byte[] decodedSolution = decoder.decode(solution);

        Assert.assertTrue(Stream.of(guesses)
                .anyMatch(guess -> {
                    Object[] current = new Object[]{guess};
                    Object[] expected = new Object[]{decodedSolution};
                    return Arrays.deepEquals(current, expected);
                }));
    }
}
