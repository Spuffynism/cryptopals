package xyz.ndlr.set_1;

import xyz.ndlr.utill.ArrayUtil;

import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

public class Challenge8 {
    public static final int AES_BLOCK_SIZE = 16;

    private final ArrayUtil arrayUtil;
    private final Base64.Encoder encoder;

    public Challenge8(ArrayUtil arrayUtil) {
        this.arrayUtil = arrayUtil;
        this.encoder = Base64.getEncoder();
    }

    public byte[] detectAESinECBMode(byte[][] ciphertexts) {
        byte[] encryptedWithECB = new byte[0];

        for (byte[] ciphertext : ciphertexts) {
            byte[][] blocks = arrayUtil
                    .splitIntoBlocks(ciphertext, AES_BLOCK_SIZE);

            if (this.findDuplicatesCount(blocks) != 0) {
                encryptedWithECB = ciphertext;
                break;
            }
        }

        return encryptedWithECB;
    }

    private int findDuplicatesCount(byte[][] bytes) {
        String[] base64Hashes = new String[bytes.length];

        for (int i = 0; i < bytes.length; i++) {
            base64Hashes[i] = encoder.encodeToString(bytes[i]);
        }

        Set<String> set = new HashSet<>(Arrays.asList(base64Hashes));

        return bytes.length - set.size();
    }
}
