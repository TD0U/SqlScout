package burp.xiasql;

public final class ResponseComparator {
    private static final int HEAD_SIZE = 8192;
    private static final int TAIL_SIZE = 4096;

    public ResponseComparisonResult compare(String baselineBody, String currentBody, int originalLength, int baselineLength, int currentLength) {
        String normalizedBaseline = baselineBody == null ? "" : baselineBody;
        String normalizedCurrent = currentBody == null ? "" : currentBody;
        double similarity = similarityScore(normalizedBaseline, normalizedCurrent);
        return new ResponseComparisonResult(
                originalLength,
                baselineLength,
                currentLength,
                baselineLength - currentLength,
                originalLength - currentLength,
                similarity);
    }

    private double similarityScore(String baselineBody, String currentBody) {
        if (baselineBody.equals(currentBody)) {
            return 1.0;
        }
        if (baselineBody.isEmpty() || currentBody.isEmpty()) {
            return 0.0;
        }

        String left = shrinkForComparison(baselineBody);
        String right = shrinkForComparison(currentBody);
        String[] trimmed = trimSharedEdges(left, right);
        left = trimmed[0];
        right = trimmed[1];
        if (left.isEmpty() && right.isEmpty()) {
            return 1.0;
        }
        if (left.isEmpty() || right.isEmpty()) {
            return 0.0;
        }

        int maxLength = Math.max(left.length(), right.length());
        int distance = levenshteinDistance(left, right);
        return 1.0 - ((double) distance / (double) maxLength);
    }

    private String shrinkForComparison(String body) {
        if (body.length() <= HEAD_SIZE + TAIL_SIZE) {
            return body;
        }
        return body.substring(0, HEAD_SIZE) + body.substring(body.length() - TAIL_SIZE);
    }

    private String[] trimSharedEdges(String left, String right) {
        int prefixLength = 0;
        int maxPrefix = Math.min(left.length(), right.length());
        while (prefixLength < maxPrefix && left.charAt(prefixLength) == right.charAt(prefixLength)) {
            prefixLength++;
        }

        int leftEnd = left.length();
        int rightEnd = right.length();
        while (leftEnd > prefixLength && rightEnd > prefixLength && left.charAt(leftEnd - 1) == right.charAt(rightEnd - 1)) {
            leftEnd--;
            rightEnd--;
        }

        return new String[]{
                left.substring(prefixLength, leftEnd),
                right.substring(prefixLength, rightEnd)
        };
    }

    private int levenshteinDistance(String left, String right) {
        int[] previous = new int[right.length() + 1];
        int[] current = new int[right.length() + 1];

        for (int j = 0; j <= right.length(); j++) {
            previous[j] = j;
        }

        for (int i = 1; i <= left.length(); i++) {
            current[0] = i;
            char leftChar = left.charAt(i - 1);
            for (int j = 1; j <= right.length(); j++) {
                int cost = leftChar == right.charAt(j - 1) ? 0 : 1;
                current[j] = Math.min(
                        Math.min(current[j - 1] + 1, previous[j] + 1),
                        previous[j - 1] + cost);
            }

            int[] swap = previous;
            previous = current;
            current = swap;
        }

        return previous[right.length()];
    }
}
