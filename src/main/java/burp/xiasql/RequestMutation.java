package burp.xiasql;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;

public final class RequestMutation {
    private final String parameterName;
    private final String originalValue;
    private final String mutatedValue;
    private final HttpParameterType parameterType;
    private final String mutatorName;
    private final HttpRequest request;
    private final int highlightStart;
    private final int highlightEnd;

    public RequestMutation(String parameterName, String originalValue, String mutatedValue,
            HttpParameterType parameterType, String mutatorName, HttpRequest request, int highlightStart, int highlightEnd) {
        this.parameterName = parameterName;
        this.originalValue = originalValue;
        this.mutatedValue = mutatedValue;
        this.parameterType = parameterType;
        this.mutatorName = mutatorName;
        this.request = request;
        this.highlightStart = highlightStart;
        this.highlightEnd = highlightEnd;
    }

    public String parameterName() {
        return parameterName;
    }

    public String originalValue() {
        return originalValue;
    }

    public String mutatedValue() {
        return mutatedValue;
    }

    public HttpParameterType parameterType() {
        return parameterType;
    }

    public String mutatorName() {
        return mutatorName;
    }

    public HttpRequest request() {
        return request;
    }

    public int highlightStart() {
        return highlightStart;
    }

    public int highlightEnd() {
        return highlightEnd;
    }

    public boolean hasHighlight() {
        return highlightStart >= 0 && highlightEnd > highlightStart;
    }
}
