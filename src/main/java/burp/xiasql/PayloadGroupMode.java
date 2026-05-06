package burp.xiasql;

public enum PayloadGroupMode {
    AUTO("auto"),
    DEFAULT("default"),
    ORDER("order"),
    TIME("time"),
    ERROR("error"),
    CUSTOM("custom");

    private final String id;

    PayloadGroupMode(String id) {
        this.id = id;
    }

    public String id() {
        return id;
    }

    public static PayloadGroupMode fromId(String id) {
        for (PayloadGroupMode mode : values()) {
            if (mode.id.equalsIgnoreCase(id)) {
                return mode;
            }
        }
        return AUTO;
    }
}
