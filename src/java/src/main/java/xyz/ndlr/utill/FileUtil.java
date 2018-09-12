package xyz.ndlr.utill;

import java.io.File;
import java.io.IOException;
import java.util.Base64;
import java.util.Scanner;

public class FileUtil {
    private final Base64.Decoder base64Decoder;

    public enum Encoding {
        BASE64,
        HEX,
        TEXT
    }

    private ConvertionHelper convertionHelper;

    public FileUtil(ConvertionHelper convertionHelper) {
        this.convertionHelper = convertionHelper;
        base64Decoder = Base64.getDecoder();
    }

    public byte[] getResource(String fileName, Encoding encoding) {
        byte[] resource = this.getResource(fileName);

        byte[] decodedResource;
        switch (encoding) {
            case BASE64:
                decodedResource = base64Decoder.decode(resource);
                break;
            case HEX:
                decodedResource = convertionHelper.hexBytesToBytes(resource);
                break;
            case TEXT:
            default:
                decodedResource = resource;
                break;
        }

        return decodedResource;
    }

    public byte[] getResource(String fileName) {
        StringBuilder builder = new StringBuilder();

        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource(fileName).getFile());

        try (Scanner scanner = new Scanner(file)) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                builder.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return convertionHelper.stringToBytes(builder.toString());
    }

    public byte[] getSolution(String fileName, Encoding encoding) {
        return this.getChallengeData("solutions/" + fileName, encoding);
    }

    public byte[] getChallengeData(String fileName, Encoding encoding) {
        return this.getResource("challenge_data/" + fileName, encoding);
    }
}
