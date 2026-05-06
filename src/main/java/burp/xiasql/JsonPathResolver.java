package burp.xiasql;

public final class JsonPathResolver {
    private final String text;
    private final int targetOffset;
    private int index;

    private JsonPathResolver(String text, int targetOffset) {
        this.text = text;
        this.targetOffset = targetOffset;
    }

    public static String resolve(String text, int targetOffset) {
        if (text == null || text.trim().isEmpty()) {
            return "";
        }

        JsonPathResolver resolver = new JsonPathResolver(text, targetOffset);
        resolver.skipWhitespace();
        String path = resolver.parseValue("");
        return path == null ? "" : path;
    }

    private String parseValue(String path) {
        skipWhitespace();
        if (index >= text.length()) {
            return null;
        }

        char ch = text.charAt(index);
        if (ch == '{') {
            return parseObject(path);
        }
        if (ch == '[') {
            return parseArray(path);
        }
        if (ch == '"') {
            return parseStringValue(path);
        }
        return parseLiteralValue(path);
    }

    private String parseObject(String path) {
        index++;
        skipWhitespace();
        if (index < text.length() && text.charAt(index) == '}') {
            index++;
            return null;
        }

        while (index < text.length()) {
            skipWhitespace();
            String key = parseQuotedString();
            skipWhitespace();
            if (index < text.length() && text.charAt(index) == ':') {
                index++;
            }

            String childPath = path.isEmpty() ? key : path + "." + key;
            String result = parseValue(childPath);
            if (result != null) {
                return result;
            }

            skipWhitespace();
            if (index < text.length() && text.charAt(index) == ',') {
                index++;
                continue;
            }
            if (index < text.length() && text.charAt(index) == '}') {
                index++;
                break;
            }
        }
        return null;
    }

    private String parseArray(String path) {
        index++;
        skipWhitespace();
        if (index < text.length() && text.charAt(index) == ']') {
            index++;
            return null;
        }

        int elementIndex = 0;
        while (index < text.length()) {
            String childPath = path + "[" + elementIndex + "]";
            String result = parseValue(childPath);
            if (result != null) {
                return result;
            }

            skipWhitespace();
            if (index < text.length() && text.charAt(index) == ',') {
                index++;
                elementIndex++;
                continue;
            }
            if (index < text.length() && text.charAt(index) == ']') {
                index++;
                break;
            }
        }
        return null;
    }

    private String parseStringValue(String path) {
        int openingQuote = index;
        index++;
        int contentStart = index;
        boolean escaped = false;

        while (index < text.length()) {
            char ch = text.charAt(index);
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                break;
            }
            index++;
        }

        int contentEnd = index;
        if (targetOffset >= contentStart && targetOffset <= contentEnd) {
            return path;
        }
        if (index < text.length() && text.charAt(index) == '"') {
            index++;
        } else {
            index = Math.max(index, openingQuote + 1);
        }
        return null;
    }

    private String parseLiteralValue(String path) {
        int start = index;
        while (index < text.length()) {
            char ch = text.charAt(index);
            if (ch == ',' || ch == '}' || ch == ']' || Character.isWhitespace(ch)) {
                break;
            }
            index++;
        }

        int end = index;
        if (targetOffset >= start && targetOffset <= end) {
            return path;
        }
        return null;
    }

    private String parseQuotedString() {
        skipWhitespace();
        if (index >= text.length() || text.charAt(index) != '"') {
            return "";
        }

        index++;
        StringBuilder builder = new StringBuilder();
        boolean escaped = false;
        while (index < text.length()) {
            char ch = text.charAt(index++);
            if (escaped) {
                builder.append(ch);
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                break;
            } else {
                builder.append(ch);
            }
        }
        return builder.toString();
    }

    private void skipWhitespace() {
        while (index < text.length() && Character.isWhitespace(text.charAt(index))) {
            index++;
        }
    }
}
