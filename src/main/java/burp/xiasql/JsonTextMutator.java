package burp.xiasql;

public final class JsonTextMutator {
    private static final String JSON_NUMBER_PATTERN = "-?(0|[1-9]\\d*)(\\.\\d+)?([eE][+-]?\\d+)?";

    private JsonTextMutator() {
    }

    public static JsonTextMutationResult mutate(String jsonText, JsonLeaf leaf, String mutatedValue) {
        String replacement = replacementFor(leaf, mutatedValue);
        if (replacement == null) {
            return null;
        }

        String updated = jsonText.substring(0, leaf.start()) + replacement + jsonText.substring(leaf.end());
        int highlightStart = leaf.start();
        int highlightEnd = leaf.start() + replacement.length();
        if (!leaf.quoted() && replacement.length() >= 2 && replacement.charAt(0) == '"' && replacement.charAt(replacement.length() - 1) == '"') {
            highlightStart++;
            highlightEnd--;
        }
        return new JsonTextMutationResult(updated, highlightStart, highlightEnd, leaf.kind().name().toLowerCase());
    }

    private static String replacementFor(JsonLeaf leaf, String mutatedValue) {
        switch (leaf.kind()) {
            case STRING:
                return escapeJson(mutatedValue);
            case NUMBER:
                if (mutatedValue.matches(JSON_NUMBER_PATTERN)) {
                    return mutatedValue;
                }
                return "\"" + escapeJson(mutatedValue) + "\"";
            case BOOLEAN:
            case NULL:
                return null;
            case UNKNOWN:
            default:
                return "\"" + escapeJson(mutatedValue) + "\"";
        }
    }

    private static String escapeJson(String value) {
        StringBuilder escaped = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"':
                    escaped.append("\\\"");
                    break;
                case '\\':
                    escaped.append("\\\\");
                    break;
                case '\b':
                    escaped.append("\\b");
                    break;
                case '\f':
                    escaped.append("\\f");
                    break;
                case '\n':
                    escaped.append("\\n");
                    break;
                case '\r':
                    escaped.append("\\r");
                    break;
                case '\t':
                    escaped.append("\\t");
                    break;
                default:
                    escaped.append(ch);
                    break;
            }
        }
        return escaped.toString();
    }
}
