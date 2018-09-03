package xyz.ndlr.utill;

import javax.xml.bind.DatatypeConverter;

public class ConvertHelper {
    /**
     * Converts a hexadecimal string to a byte array
     *
     * @param hexadecimalString
     * @return list of chars
     */
    public byte[] hexToBytes(String hexadecimalString) {
        return DatatypeConverter.parseHexBinary(hexadecimalString);
    }

    public String byteArrayToHexString(byte[] characters) {
        return DatatypeConverter.printHexBinary(characters);
    }

    public String byteArrayToString(byte[] characters) {
        return new String(characters);
    }
}
