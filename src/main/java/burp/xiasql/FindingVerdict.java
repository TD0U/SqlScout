package burp.xiasql;

public enum FindingVerdict {
    INFO("INFO", "信息"),
    SUSPECTED("SUSPECTED", "疑似"),
    CONFIRMED("CONFIRMED", "高疑似");

    private final String code;
    private final String displayName;

    FindingVerdict(String code, String displayName) {
        this.code = code;
        this.displayName = displayName;
    }

    public String code() {
        return code;
    }

    public String displayName() {
        return displayName;
    }

    public static FindingVerdict max(FindingVerdict left, FindingVerdict right) {
        return left.ordinal() >= right.ordinal() ? left : right;
    }
}
