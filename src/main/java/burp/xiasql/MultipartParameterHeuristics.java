package burp.xiasql;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

public final class MultipartParameterHeuristics {
    private MultipartParameterHeuristics() {
    }

    public static boolean shouldSkip(HttpRequest request, ParsedHttpParameter parameter) {
        if (parameter.type() != HttpParameterType.MULTIPART_ATTRIBUTE) {
            return false;
        }

        String name = parameter.name() == null ? "" : parameter.name().toLowerCase();
        if ("filename".equals(name) || "content-type".equals(name) || "contenttype".equals(name)) {
            return true;
        }

        String rawRequest = request.toString();
        int valueStart = parameter.valueOffsets().startIndexInclusive();
        int valueEnd = parameter.valueOffsets().endIndexExclusive();
        if (valueStart < request.bodyOffset() || valueEnd > rawRequest.length() || valueStart >= valueEnd) {
            return false;
        }

        int partHeaderStart = rawRequest.lastIndexOf("\r\n--", valueStart);
        if (partHeaderStart < 0) {
            partHeaderStart = request.bodyOffset();
        } else {
            partHeaderStart += 2;
        }

        int headerBlockEnd = rawRequest.indexOf("\r\n\r\n", partHeaderStart);
        if (headerBlockEnd < 0 || headerBlockEnd > valueStart) {
            return false;
        }

        String headers = rawRequest.substring(partHeaderStart, headerBlockEnd).toLowerCase();
        if (headers.contains("filename=")) {
            return true;
        }
        if (headers.contains("content-type:")) {
            String bodyValue = rawRequest.substring(valueStart, valueEnd);
            if (looksLikeBinary(bodyValue)) {
                return true;
            }
        }

        return false;
    }

    private static boolean looksLikeBinary(String value) {
        int sampleLength = Math.min(value.length(), 128);
        for (int i = 0; i < sampleLength; i++) {
            char ch = value.charAt(i);
            if (Character.isISOControl(ch) && ch != '\r' && ch != '\n' && ch != '\t') {
                return true;
            }
        }
        return false;
    }
}
