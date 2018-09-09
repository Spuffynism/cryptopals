package xyz.ndlr.set_1;

public class KeyDistance implements Comparable<KeyDistance> {
    /**
     * The comparison result is casted to an int, so we shift the numbers to the
     * left not to lose too much precision.
     */
    private static final int COMPARISON_PRECISION = 100_000;

    private double distance;
    private int keySize;

    public KeyDistance(double distance, int keySize) {
        this.distance = distance;
        this.keySize = keySize;
    }

    public double getDistance() {
        return distance;
    }

    public int getKeySize() {
        return keySize;
    }

    @Override
    public int compareTo(KeyDistance other) {
        return (int) ((this.distance - other.distance) * COMPARISON_PRECISION);
    }

    @Override
    public String toString() {
        return "KeyDistance{" +
                "distance=" + distance +
                ", keySize=" + keySize +
                '}';
    }
}
