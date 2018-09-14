package xyz.ndlr.set_2;

import xyz.ndlr.utill.AbstractChallengeFactory;

public class Set2ChallengeFactory extends AbstractChallengeFactory {
    public Challenge1 getChallenge1() {
        return new Challenge1(this.getConvertionHelper());
    }
}
