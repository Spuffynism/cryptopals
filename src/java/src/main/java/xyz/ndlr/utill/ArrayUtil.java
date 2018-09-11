package xyz.ndlr.utill;

import java.util.Arrays;

public class ArrayUtil {
    /**
     * Splits an array into blocks of size.
     *
     * @param bytes the bytes to split
     * @param size  the blocks size
     * @return splitted bytes
     */
    public byte[][] splitIntoBlocks(byte[] bytes, int size) {
        byte[][] blocks = new byte[(bytes.length + size - 1) / size][size];

        for (int i = 0; i < blocks.length; i++) {
            int from = i * size;
            int to = from + size;

            blocks[i] = Arrays.copyOfRange(bytes, from, to);
        }

        return blocks;
    }

    /**
     * Transposes a matrix.
     *
     * @param matrix to transpose
     * @return transposed matrix
     */
    public byte[][] transpose(byte[][] matrix) {
        byte[][] transposed = new byte[matrix[0].length][matrix.length];
        for (int i = 0; i < matrix.length; i++) {
            for (int j = 0; j < matrix[0].length; j++) {
                transposed[j][i] = matrix[i][j];
            }
        }

        return transposed;
    }
}
