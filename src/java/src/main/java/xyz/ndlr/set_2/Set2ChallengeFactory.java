package xyz.ndlr.set_2;

import xyz.ndlr.utill.AbstractChallengeFactory;

public class Set2ChallengeFactory extends AbstractChallengeFactory {
    public Challenge9 getChallenge9() {
        return new Challenge9(this.getConvertionHelper());
    }
}
