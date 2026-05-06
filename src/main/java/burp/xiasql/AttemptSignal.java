package burp.xiasql;

public enum AttemptSignal {
    LENGTH_DELTA("Length"),
    ERROR_PATTERN("Error"),
    TIME_DELAY("Time"),
    CUSTOM_PAYLOAD("Custom");

    private final String label;

    AttemptSignal(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
