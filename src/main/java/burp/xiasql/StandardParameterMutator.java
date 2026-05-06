package burp.xiasql;

import static burp.api.montoya.http.message.params.HttpParameter.parameter;

import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

public final class StandardParameterMutator implements RequestMutator {
    @Override
    public boolean supports(HttpRequest request, ParsedHttpParameter parameter) {
        HttpParameterType type = parameter.type();
        if (type == HttpParameterType.JSON) {
            return false;
        }
        if (type == HttpParameterType.BODY && request.contentType() == ContentType.JSON) {
            return false;
        }
        return type == HttpParameterType.URL
                || type == HttpParameterType.BODY
                || type == HttpParameterType.COOKIE
                || type == HttpParameterType.MULTIPART_ATTRIBUTE;
    }

    @Override
    public RequestMutation mutate(HttpRequest request, ParsedHttpParameter parameter, String mutatedValue) {
        HttpRequest mutatedRequest = request.withParameter(parameter(parameter.name(), mutatedValue, parameter.type()));
        ParsedHttpParameter mutatedParameter = mutatedRequest.parameter(parameter.name(), parameter.type());
        int highlightStart = -1;
        int highlightEnd = -1;
        if (mutatedParameter != null) {
            highlightStart = mutatedParameter.valueOffsets().startIndexInclusive();
            highlightEnd = mutatedParameter.valueOffsets().endIndexExclusive();
        }
        return new RequestMutation(parameter.name(), parameter.value(), mutatedValue, parameter.type(), "standard", mutatedRequest, highlightStart, highlightEnd);
    }
}
