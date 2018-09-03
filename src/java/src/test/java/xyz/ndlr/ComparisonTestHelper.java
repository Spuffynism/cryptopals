package java.xyz.ndlr;

import org.junit.Assert;
import xyz.ndlr.set_1.Challenge1;
import xyz.ndlr.utill.ConvertHelper;

import java.util.function.Function;

public class ComparisonTestHelper {
    public void areEqual(String expected, String input, Function<byte[], byte[]> operation) {
        ConvertHelper convertHelper = new ConvertHelper();
        Challenge1 challenge1 = new Challenge1(convertHelper);

        byte[] inputCharacters = convertHelper.hexToBytes(input);
        byte[] expectedCharacters = expected.getBytes();

        byte[] actualCharacters = operation.apply(inputCharacters);

        Assert.assertEquals(expectedCharacters, actualCharacters);
    }
}
