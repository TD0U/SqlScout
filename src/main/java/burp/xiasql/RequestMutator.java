package burp.xiasql;

import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

public interface RequestMutator {
    boolean supports(HttpRequest request, ParsedHttpParameter parameter);

    RequestMutation mutate(HttpRequest request, ParsedHttpParameter parameter, String mutatedValue);
}
