package burp.xiasql;

import static burp.api.montoya.http.message.params.HttpParameter.parameter;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

public final class HiddenParameterPoint {
    private final HttpRequest request;
    private final String parameterName;
    private final HttpParameterType parameterType;
    private final ParameterProfile profile;

    public HiddenParameterPoint(HttpRequest request, String parameterName, HttpParameterType parameterType) {
        this.request = request;
        this.parameterName = parameterName;
        this.parameterType = parameterType;
        this.profile = ParameterClassifier.classifyHidden(parameterName);
    }

    public ParameterProfile profile() {
        return profile;
    }

    public RequestMutation mutate(String mutatedValue) {
        HttpRequest mutatedRequest = request.withAddedParameters(parameter(parameterName, mutatedValue, parameterType));
        ParsedHttpParameter addedParameter = mutatedRequest.parameter(parameterName, parameterType);
        if (addedParameter == null) {
            return null;
        }

        int highlightStart = addedParameter.valueOffsets().startIndexInclusive();
        int highlightEnd = addedParameter.valueOffsets().endIndexExclusive();
        return new RequestMutation(parameterName, "", mutatedValue, parameterType, "hidden-parameter", mutatedRequest, highlightStart, highlightEnd);
    }
}
