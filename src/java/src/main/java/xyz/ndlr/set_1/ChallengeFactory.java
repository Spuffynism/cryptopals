package xyz.ndlr.set_1;

import xyz.ndlr.utill.ArrayUtil;
import xyz.ndlr.utill.ConvertionHelper;

public class ChallengeFactory {
    private ArrayUtil arrayUtil;
    private ConvertionHelper convertionHelper;

    private ArrayUtil getArrayUtil() {
        if (arrayUtil == null)
            arrayUtil = new ArrayUtil();

        return arrayUtil;
    }

    private ConvertionHelper getConvertionHelper() {
        if (convertionHelper == null)
            convertionHelper = new ConvertionHelper();

        return convertionHelper;
    }

    public Challenge2 getChallenge2() {
        return new Challenge2();
    }

    public Challenge3 getChallenge3() {
        return new Challenge3();
    }

    public Challenge4 getChallenge4() {
        return new Challenge4(getChallenge3(), getConvertionHelper());
    }

    public Challenge5 getChallenge5() {
        return new Challenge5();
    }

    public Challenge6 getChallenge6() {
        return new Challenge6(getChallenge3(), getChallenge4(), getChallenge5(), getArrayUtil());
    }

    public Challenge7 getChallenge7() {
        return new Challenge7();
    }
}
