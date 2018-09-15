package xyz.ndlr.set_2;

import xyz.ndlr.utill.ConvertionHelper;

import java.util.Arrays;

public class Challenge9 {

    private final ConvertionHelper convertionHelper;

    public Challenge9(ConvertionHelper convertionHelper) {
        this.convertionHelper = convertionHelper;
    }

    /**
     * Pads a block with PKCS#7 padding.
     *
     * @param block the block to pad
     * @param size  the desired block size
     * @return the padded block
     */
    public byte[] pckcs7Pad(byte[] block, int size) {
        byte[] paddingBytes = this.generatePaddingBytes(size - block.length);
        byte[] paddedBlock = new byte[block.length + paddingBytes.length];

        System.arraycopy(block, 0, paddedBlock, 0, block.length);
        System.arraycopy(paddingBytes, 0, paddedBlock, block.length, paddingBytes.length);

        return paddedBlock;
    }

    public byte[] generatePaddingBytes(int length) {
        int paddingBytesLength = 4;
        byte[] paddingBytePrefix = convertionHelper.stringToBytes("\\x");

        byte[] paddingBytes = new byte[length * paddingBytesLength];

        for (int i = 0; i < length; i++) {
            byte[] currentPaddingByte =
                    Arrays.copyOf(paddingBytePrefix, paddingBytesLength);

            addPaddingSizeBytes(currentPaddingByte, length);

            int paddingStartPosition = i * paddingBytesLength;
            for (int j = paddingStartPosition; j < paddingStartPosition +
                    paddingBytesLength; j++) {
                paddingBytes[j] = currentPaddingByte[j % paddingBytesLength];
            }
        }

        return paddingBytes;
    }

    private void addPaddingSizeBytes(byte[] currentPaddingByte, int length) {
        String padding = Integer.toHexString(length);
        if (padding.length() == 1) {
            currentPaddingByte[2] = (byte) '0';
            currentPaddingByte[3] = (byte) padding.charAt(0);

        } else {
            currentPaddingByte[2] = (byte) padding.charAt(0);
            currentPaddingByte[3] = (byte) padding.charAt(1);
        }
    }
}
