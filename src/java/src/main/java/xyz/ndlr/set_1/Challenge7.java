package xyz.ndlr.set_1;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class Challenge7 {
    private static final String AES = "AES";

    public byte[] decryptAESinECBMode(byte[] message, byte[] key) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException {
        Key AESkey = new SecretKeySpec(key, AES);
        Cipher cipher = Cipher.getInstance(AES);

        cipher.init(Cipher.DECRYPT_MODE, AESkey);

        return cipher.doFinal(message);
    }
}
