package burp.xiasql;

public final class ParameterProfile {
    public enum Category {
        GENERIC,
        NUMERIC_CONTROL,
        SORT_CONTROL
    }

    private final String displayName;
    private final String baseValue;
    private final boolean numeric;
    private final Category category;

    public ParameterProfile(String displayName, String baseValue, boolean numeric, Category category) {
        this.displayName = displayName;
        this.baseValue = baseValue;
        this.numeric = numeric;
        this.category = category;
    }

    public String displayName() {
        return displayName;
    }

    public String baseValue() {
        return baseValue;
    }

    public boolean numeric() {
        return numeric;
    }

    public Category category() {
        return category;
    }
}
