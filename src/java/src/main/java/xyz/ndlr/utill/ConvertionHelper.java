package xyz.ndlr.utill;

import javax.xml.bind.DatatypeConverter;
import java.util.Arrays;

public class ConvertionHelper {
    /**
     * Converts a hexadecimal string to a byte array
     *
     * @param hexadecimalString
     * @return list of chars
     */
    public byte[] hexToBytes(String hexadecimalString) {
        if (hexadecimalString.contains("\n")) {
            String[] splitted = hexadecimalString.split("\n");

            return DatatypeConverter.parseHexBinary(String.join("", splitted));
        }

        return DatatypeConverter.parseHexBinary(hexadecimalString);
    }

    public String bytesToHex(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }

    public String bytesToString(byte[] bytes) {
        return new String(bytes);
    }

    public byte[] stringToBytes(String string) {
        return string.getBytes();
    }

    public String hexToString(String hex) {
        return this.bytesToString(this.hexToBytes(hex));
    }
}
