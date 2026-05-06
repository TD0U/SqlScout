package burp.xiasql;

import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.Arrays;
import java.util.List;

public final class RequestMutationService {
    private final List<RequestMutator> mutators;

    public RequestMutationService(RequestMutator... mutators) {
        this.mutators = Arrays.asList(mutators);
    }

    public RequestMutation mutate(HttpRequest request, ParsedHttpParameter parameter, String mutatedValue) {
        for (RequestMutator mutator : mutators) {
            if (mutator.supports(request, parameter)) {
                return mutator.mutate(request, parameter, mutatedValue);
            }
        }
        return null;
    }
}
