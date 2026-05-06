package burp.xiasql;

import static burp.api.montoya.http.message.params.HttpParameter.parameter;

import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

public final class JsonParameterMutator implements RequestMutator {
    private static final String JSON_NUMBER_PATTERN = "-?(0|[1-9]\\d*)(\\.\\d+)?([eE][+-]?\\d+)?";

    @Override
    public boolean supports(HttpRequest request, ParsedHttpParameter parameter) {
        return parameter.type() == HttpParameterType.JSON || request.contentType() == ContentType.JSON;
    }

    @Override
    public RequestMutation mutate(HttpRequest request, ParsedHttpParameter parameter, String mutatedValue) {
        String displayName = resolveDisplayName(request, parameter);
        HttpRequest mutatedRequest = request.withParameter(parameter(parameter.name(), mutatedValue, parameter.type()));
        if (isChanged(request, mutatedRequest, parameter.value(), mutatedValue)) {
            ParsedHttpParameter mutatedParameter = mutatedRequest.parameter(parameter.name(), parameter.type());
            int highlightStart = -1;
            int highlightEnd = -1;
            if (mutatedParameter != null) {
                highlightStart = mutatedParameter.valueOffsets().startIndexInclusive();
                highlightEnd = mutatedParameter.valueOffsets().endIndexExclusive();
            }
            return new RequestMutation(displayName, parameter.value(), mutatedValue, parameter.type(), "json-parameter", mutatedRequest, highlightStart, highlightEnd);
        }

        return mutateJsonBodyByOffsets(request, parameter, mutatedValue, displayName);
    }

    private RequestMutation mutateJsonBodyByOffsets(HttpRequest request, ParsedHttpParameter parameter, String mutatedValue, String displayName) {
        String rawRequest = request.toString();
        int bodyOffset = request.bodyOffset();
        int start = parameter.valueOffsets().startIndexInclusive();
        int end = parameter.valueOffsets().endIndexExclusive();
        if (start < bodyOffset || end > rawRequest.length() || start >= end) {
            return null;
        }

        JsonValueKind valueKind = detectValueKind(rawRequest, start, end);
        boolean quotedValue = isQuotedValue(rawRequest, start, end);
        String replacement = replacementFor(valueKind, mutatedValue);
        if (replacement == null) {
            return null;
        }

        String updatedRequest = rawRequest.substring(0, start) + replacement + rawRequest.substring(end);
        HttpRequest fallbackRequest = HttpRequest.httpRequest(request.httpService(), updatedRequest);
        if (!isChanged(request, fallbackRequest, parameter.value(), mutatedValue)) {
            return null;
        }

        int[] highlightRange = highlightRangeForReplacement(start, replacement, quotedValue, valueKind);
        return new RequestMutation(displayName, parameter.value(), mutatedValue, parameter.type(), "json-offset-" + valueKind.label(), fallbackRequest,
                highlightRange[0], highlightRange[1]);
    }

    private String resolveDisplayName(HttpRequest request, ParsedHttpParameter parameter) {
        String rawRequest = request.toString();
        int bodyOffset = request.bodyOffset();
        int start = parameter.valueOffsets().startIndexInclusive();
        if (bodyOffset < 0 || bodyOffset >= rawRequest.length() || start < bodyOffset || start > rawRequest.length()) {
            return parameter.name();
        }

        String body = rawRequest.substring(bodyOffset);
        String jsonPath = JsonPathResolver.resolve(body, start - bodyOffset);
        return jsonPath.isEmpty() ? parameter.name() : jsonPath;
    }

    private boolean isChanged(HttpRequest original, HttpRequest mutated, String originalValue, String mutatedValue) {
        if (mutated == null) {
            return false;
        }
        if (originalValue.equals(mutatedValue)) {
            return !original.toString().equals(mutated.toString());
        }
        return mutated.toString().contains(mutatedValue) && !original.toString().equals(mutated.toString());
    }

    private JsonValueKind detectValueKind(String rawRequest, int start, int end) {
        boolean quotedValue = isQuotedValue(rawRequest, start, end);
        if (quotedValue) {
            return JsonValueKind.STRING;
        }

        String literal = rawRequest.substring(start, end).trim();
        if (literal.matches(JSON_NUMBER_PATTERN)) {
            return JsonValueKind.NUMBER;
        }
        if ("true".equals(literal) || "false".equals(literal)) {
            return JsonValueKind.BOOLEAN;
        }
        if ("null".equals(literal)) {
            return JsonValueKind.NULL;
        }
        return JsonValueKind.UNKNOWN;
    }

    private boolean isQuotedValue(String rawRequest, int start, int end) {
        return start > 0 && end < rawRequest.length() && rawRequest.charAt(start - 1) == '"' && rawRequest.charAt(end) == '"';
    }

    private String replacementFor(JsonValueKind valueKind, String mutatedValue) {
        switch (valueKind) {
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

    private int[] highlightRangeForReplacement(int start, String replacement, boolean quotedValue, JsonValueKind valueKind) {
        if (replacement == null || replacement.isEmpty()) {
            return new int[]{-1, -1};
        }
        if (quotedValue || valueKind == JsonValueKind.STRING) {
            return new int[]{start, start + replacement.length()};
        }
        if (replacement.length() >= 2 && replacement.charAt(0) == '"' && replacement.charAt(replacement.length() - 1) == '"') {
            return new int[]{start + 1, start + replacement.length() - 1};
        }
        return new int[]{start, start + replacement.length()};
    }

    private String escapeJson(String value) {
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

    private enum JsonValueKind {
        STRING("string"),
        NUMBER("number"),
        BOOLEAN("boolean"),
        NULL("null"),
        UNKNOWN("unknown");

        private final String label;

        JsonValueKind(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }
}
