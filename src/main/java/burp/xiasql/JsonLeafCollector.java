package burp.xiasql;

import java.util.ArrayList;
import java.util.List;

public final class JsonLeafCollector {
    private static final String JSON_NUMBER_PATTERN = "-?(0|[1-9]\\d*)(\\.\\d+)?([eE][+-]?\\d+)?";

    private final String text;
    private int index;

    private JsonLeafCollector(String text) {
        this.text = text;
    }

    public static List<JsonLeaf> collect(String text) {
        if (text == null) {
            return java.util.Collections.emptyList();
        }
        JsonLeafCollector collector = new JsonLeafCollector(text);
        List<JsonLeaf> leaves = new ArrayList<JsonLeaf>();
        collector.skipWhitespace();
        collector.parseValue("", leaves);
        return leaves;
    }

    private void parseValue(String path, List<JsonLeaf> leaves) {
        skipWhitespace();
        if (index >= text.length()) {
            return;
        }
        char ch = text.charAt(index);
        if (ch == '{') {
            parseObject(path, leaves);
        } else if (ch == '[') {
            parseArray(path, leaves);
        } else if (ch == '"') {
            parseStringValue(path, leaves);
        } else {
            parseLiteralValue(path, leaves);
        }
    }

    private void parseObject(String path, List<JsonLeaf> leaves) {
        index++;
        skipWhitespace();
        if (index < text.length() && text.charAt(index) == '}') {
            index++;
            return;
        }

        while (index < text.length()) {
            skipWhitespace();
            String key = parseQuotedString();
            skipWhitespace();
            if (index < text.length() && text.charAt(index) == ':') {
                index++;
            }
            String childPath = path.isEmpty() ? key : path + "." + key;
            parseValue(childPath, leaves);

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
    }

    private void parseArray(String path, List<JsonLeaf> leaves) {
        index++;
        skipWhitespace();
        if (index < text.length() && text.charAt(index) == ']') {
            index++;
            return;
        }

        int itemIndex = 0;
        while (index < text.length()) {
            parseValue(path + "[" + itemIndex + "]", leaves);
            skipWhitespace();
            if (index < text.length() && text.charAt(index) == ',') {
                index++;
                itemIndex++;
                continue;
            }
            if (index < text.length() && text.charAt(index) == ']') {
                index++;
                break;
            }
        }
    }

    private void parseStringValue(String path, List<JsonLeaf> leaves) {
        int startQuote = index;
        index++;
        int contentStart = index;
        StringBuilder value = new StringBuilder();
        boolean escaped = false;
        while (index < text.length()) {
            char ch = text.charAt(index);
            if (escaped) {
                value.append(ch);
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                break;
            } else {
                value.append(ch);
            }
            index++;
        }
        int contentEnd = index;
        if (index < text.length() && text.charAt(index) == '"') {
            index++;
        } else {
            index = Math.max(index, startQuote + 1);
        }
        leaves.add(new JsonLeaf(path, value.toString(), contentStart, contentEnd, JsonLeaf.Kind.STRING, true));
    }

    private void parseLiteralValue(String path, List<JsonLeaf> leaves) {
        int start = index;
        while (index < text.length()) {
            char ch = text.charAt(index);
            if (ch == ',' || ch == '}' || ch == ']' || Character.isWhitespace(ch)) {
                break;
            }
            index++;
        }
        int end = index;
        String value = text.substring(start, end).trim();
        leaves.add(new JsonLeaf(path, value, start, end, classifyLiteral(value), false));
    }

    private JsonLeaf.Kind classifyLiteral(String value) {
        if (value.matches(JSON_NUMBER_PATTERN)) {
            return JsonLeaf.Kind.NUMBER;
        }
        if ("true".equals(value) || "false".equals(value)) {
            return JsonLeaf.Kind.BOOLEAN;
        }
        if ("null".equals(value)) {
            return JsonLeaf.Kind.NULL;
        }
        return JsonLeaf.Kind.UNKNOWN;
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
