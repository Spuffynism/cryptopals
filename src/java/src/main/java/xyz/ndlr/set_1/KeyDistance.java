package xyz.ndlr.set_1;

public class KeyDistance implements Comparable<KeyDistance> {
    private static final int MIN_KEY_SIZE = 2;

    private float distance;
    private int keySize;

    public KeyDistance(float distance, int keySize) {
        this.distance = distance;
        this.keySize = keySize;
    }

    public float getDistance() {
        return distance;
    }

    public int getKeySize() {
        return keySize;
    }

    @Override
    public int compareTo(KeyDistance other) {
        return (int) (this.distance - other.distance);
    }

    @Override
    public String toString() {
        return "KeyDistance{" +
                "distance=" + distance +
                ", keySize=" + keySize +
                '}';
    }
}
