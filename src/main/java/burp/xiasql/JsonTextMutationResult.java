package burp.xiasql;

public final class JsonTextMutationResult {
    private final String updatedJson;
    private final int highlightStart;
    private final int highlightEnd;
    private final String mutatorSuffix;

    public JsonTextMutationResult(String updatedJson, int highlightStart, int highlightEnd, String mutatorSuffix) {
        this.updatedJson = updatedJson;
        this.highlightStart = highlightStart;
        this.highlightEnd = highlightEnd;
        this.mutatorSuffix = mutatorSuffix;
    }

    public String updatedJson() {
        return updatedJson;
    }

    public int highlightStart() {
        return highlightStart;
    }

    public int highlightEnd() {
        return highlightEnd;
    }

    public String mutatorSuffix() {
        return mutatorSuffix;
    }
}
