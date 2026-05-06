package burp.xiasql;

import static burp.api.montoya.http.message.params.HttpParameter.parameter;

import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public final class EncodedJsonParameterPoint {
    private final HttpRequest request;
    private final ParsedHttpParameter outerParameter;
    private final JsonLeaf leaf;
    private final String decodedJson;

    public EncodedJsonParameterPoint(HttpRequest request, ParsedHttpParameter outerParameter, JsonLeaf leaf, String decodedJson) {
        this.request = request;
        this.outerParameter = outerParameter;
        this.leaf = leaf;
        this.decodedJson = decodedJson;
    }

    public String displayName() {
        return outerParameter.name() + "." + leaf.path();
    }

    public String baseValue() {
        return leaf.value();
    }

    public ParameterProfile profile() {
        return ParameterClassifier.classifyEncodedJsonLeaf(this);
    }

    public RequestMutation mutate(String mutatedValue) {
        JsonTextMutationResult mutationResult = JsonTextMutator.mutate(decodedJson, leaf, mutatedValue);
        if (mutationResult == null) {
            return null;
        }

        String encodedValue = URLEncoder.encode(mutationResult.updatedJson(), StandardCharsets.UTF_8);
        HttpRequest mutatedRequest = request.withParameter(parameter(outerParameter.name(), encodedValue, outerParameter.type()));
        ParsedHttpParameter updatedParameter = mutatedRequest.parameter(outerParameter.name(), outerParameter.type());
        if (updatedParameter == null) {
            return null;
        }

        int[] highlightRange = encodedHighlightRange(updatedParameter, mutationResult);
        int highlightStart = highlightRange[0];
        int highlightEnd = highlightRange[1];
        return new RequestMutation(displayName(), leaf.value(), mutatedValue, outerParameter.type(),
                "url-encoded-json-" + mutationResult.mutatorSuffix(), mutatedRequest, highlightStart, highlightEnd);
    }

    private int[] encodedHighlightRange(ParsedHttpParameter updatedParameter, JsonTextMutationResult mutationResult) {
        String prefix = mutationResult.updatedJson().substring(0, mutationResult.highlightStart());
        String segment = mutationResult.updatedJson().substring(mutationResult.highlightStart(), mutationResult.highlightEnd());
        String encodedPrefix = URLEncoder.encode(prefix, StandardCharsets.UTF_8);
        String encodedSegment = URLEncoder.encode(segment, StandardCharsets.UTF_8);
        int start = updatedParameter.valueOffsets().startIndexInclusive() + encodedPrefix.length();
        int end = start + encodedSegment.length();
        return new int[]{start, end};
    }

    public static String decodeIfJsonLike(String value) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }
        try {
            String decoded = URLDecoder.decode(value, StandardCharsets.UTF_8.name());
            if (!decoded.equals(value) && looksLikeJson(decoded)) {
                return decoded;
            }
        } catch (Exception ignored) {
            return null;
        }
        return null;
    }

    private static boolean looksLikeJson(String value) {
        String trimmed = value.trim();
        return (trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"));
    }
}
