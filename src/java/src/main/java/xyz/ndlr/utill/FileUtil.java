package xyz.ndlr.utill;

import java.io.File;
import java.io.IOException;
import java.util.Scanner;

public class FileUtil {
    private ConvertionHelper convertionHelper;

    public FileUtil(ConvertionHelper convertionHelper) {
        this.convertionHelper = convertionHelper;
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
}
