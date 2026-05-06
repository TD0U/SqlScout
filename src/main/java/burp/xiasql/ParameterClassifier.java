package burp.xiasql;

import burp.api.montoya.http.message.params.ParsedHttpParameter;

public final class ParameterClassifier {
    private ParameterClassifier() {
    }

    public static ParameterProfile classify(ParsedHttpParameter parameter) {
        String name = parameter.name();
        String value = parameter.value();
        return buildProfile(name, value);
    }

    public static ParameterProfile classifyEncodedJsonLeaf(EncodedJsonParameterPoint point) {
        return buildProfile(point.displayName(), point.baseValue());
    }

    public static ParameterProfile classifyHidden(String displayName) {
        return buildProfile(displayName, "");
    }

    private static ParameterProfile buildProfile(String displayName, String value) {
        String normalized = normalizeName(displayName);
        boolean numeric = value != null && value.matches("[0-9]+");

        if (containsAny(normalized, "sort", "order", "orderby", "sortfield", "sortorder", "direction")) {
            return new ParameterProfile(displayName, value, numeric, ParameterProfile.Category.SORT_CONTROL);
        }
        if (numeric || containsAny(normalized, "limit", "offset", "page", "pagesize", "pageindex", "size", "start", "end", "rownum", "id")) {
            return new ParameterProfile(displayName, value, numeric, ParameterProfile.Category.NUMERIC_CONTROL);
        }
        return new ParameterProfile(displayName, value, numeric, ParameterProfile.Category.GENERIC);
    }

    private static boolean containsAny(String value, String... needles) {
        for (String needle : needles) {
            if (value.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private static String normalizeName(String displayName) {
        return displayName == null ? "" : displayName.toLowerCase().replace("_", "").replace("-", "");
    }
}
