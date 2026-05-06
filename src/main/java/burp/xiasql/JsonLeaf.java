package burp.xiasql;

public final class JsonLeaf {
    public enum Kind {
        STRING,
        NUMBER,
        BOOLEAN,
        NULL,
        UNKNOWN
    }

    private final String path;
    private final String value;
    private final int start;
    private final int end;
    private final Kind kind;
    private final boolean quoted;

    public JsonLeaf(String path, String value, int start, int end, Kind kind, boolean quoted) {
        this.path = path;
        this.value = value;
        this.start = start;
        this.end = end;
        this.kind = kind;
        this.quoted = quoted;
    }

    public String path() {
        return path;
    }

    public String value() {
        return value;
    }

    public int start() {
        return start;
    }

    public int end() {
        return end;
    }

    public Kind kind() {
        return kind;
    }

    public boolean quoted() {
        return quoted;
    }
}
