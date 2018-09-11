package xyz.ndlr;

import org.junit.Assert;
import org.junit.Test;
import xyz.ndlr.utill.ArrayUtil;

public class ArrayUtilTest {
    @Test
    public void challenge6Transpose() {
        ArrayUtil arrayUtil = new ArrayUtil();

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

        Assert.assertArrayEquals(expected, arrayUtil.transpose(matrix));
    }

    @Test
    public void challenge6SplitIntoBlocksEven() {
        ArrayUtil arrayUtil = new ArrayUtil();

        byte[] bytes = new byte[]{2, 2, 3, 3, 4, 4};
        int blockSize = 2;
        byte[][] expected = new byte[][]{
                {2, 2},
                {3, 3},
                {4, 4}
        };

        Assert.assertArrayEquals(expected, arrayUtil.splitIntoBlocks(bytes, blockSize));
    }

    @Test
    public void challenge6SplitIntoBlocksOdd() {
        ArrayUtil arrayUtil = new ArrayUtil();

        byte[] bytes = new byte[]{2, 2, 3, 3, 4, 4, 5};
        int blockSize = 2;
        byte[][] expected = new byte[][]{
                {2, 2},
                {3, 3},
                {4, 4},
                {5, 0}
        };

        Assert.assertArrayEquals(expected, arrayUtil.splitIntoBlocks(bytes, blockSize));
    }
}
