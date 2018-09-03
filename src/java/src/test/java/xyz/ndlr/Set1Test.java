package java.xyz.ndlr;

import org.junit.Test;
import xyz.ndlr.set_1.Challenge1;
import xyz.ndlr.utill.ConvertHelper;

import java.xyz.ndlr.ComparisonTestHelper;

public class Set1Test {
    @Test
    public void challenge1() {
        ConvertHelper convertHelper = new ConvertHelper();
        Challenge1 challenge1 = new Challenge1(convertHelper);

        String input =
                "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        String expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        ComparisonTestHelper comparisonTestHelper = new ComparisonTestHelper();
        comparisonTestHelper.areEqual(expected, input, challenge1::convertHexToBase64);
    }
}
