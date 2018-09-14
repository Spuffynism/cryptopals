package xyz.ndlr.utill;

public class AbstractChallengeFactory {
    private ArrayUtil arrayUtil;
    private ConvertionHelper convertionHelper;

    protected ArrayUtil getArrayUtil() {
        if (arrayUtil == null)
            arrayUtil = new ArrayUtil();

        return arrayUtil;
    }

    protected ConvertionHelper getConvertionHelper() {
        if (convertionHelper == null)
            convertionHelper = new ConvertionHelper();

        return convertionHelper;
    }
}
