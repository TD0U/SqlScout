package burp.xiasql;

public final class ResponseComparisonResult {
    private final int originalLength;
    private final int baselineLength;
    private final int currentLength;
    private final int baselineDelta;
    private final int originalDelta;
    private final double similarity;

    public ResponseComparisonResult(int originalLength, int baselineLength, int currentLength,
            int baselineDelta, int originalDelta, double similarity) {
        this.originalLength = originalLength;
        this.baselineLength = baselineLength;
        this.currentLength = currentLength;
        this.baselineDelta = baselineDelta;
        this.originalDelta = originalDelta;
        this.similarity = similarity;
    }

    public int originalLength() {
        return originalLength;
    }

    public int baselineLength() {
        return baselineLength;
    }

    public int currentLength() {
        return currentLength;
    }

    public int baselineDelta() {
        return baselineDelta;
    }

    public int originalDelta() {
        return originalDelta;
    }

    public double similarity() {
        return similarity;
    }
}
