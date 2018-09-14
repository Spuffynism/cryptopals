package xyz.ndlr;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import xyz.ndlr.set_2.Challenge9;
import xyz.ndlr.set_2.Set2ChallengeFactory;
import xyz.ndlr.utill.ConvertionHelper;

public class Set2Test {
    private Set2ChallengeFactory challengeFactory;
    private ConvertionHelper convertionHelper;

    @Before
    public void setUp() {
        this.challengeFactory = new Set2ChallengeFactory();
        this.convertionHelper = new ConvertionHelper();
    }

    @Test
    public void challenge1() {
        Challenge9 challenge9 = challengeFactory.getChallenge9();
        String input = "YELLOW SUBMARINE";
        String expected = "YELLOW SUBMARINE\\x04\\x04\\x04\\x04";

        byte[] inputBytes = convertionHelper.stringToBytes(input);
        byte[] expectedBytes = convertionHelper.stringToBytes(expected);

        byte[] result = challenge9.pckcs7Pad(inputBytes, 20);

        Assert.assertArrayEquals(expectedBytes, result);
    }
}
