package burp.xiasql;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;

public final class XiaSqlHttpHandler implements HttpHandler {
    private final DetectionEngine engine;
    private final ExtensionState state;

    public XiaSqlHttpHandler(DetectionEngine engine, ExtensionState state) {
        this.engine = engine;
        this.state = state;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (state.enabled()) {
            ToolType toolType = responseReceived.toolSource().toolType();
            if ((toolType == ToolType.REPEATER && state.monitorRepeater()) || (toolType == ToolType.PROXY && state.monitorProxy())) {
                engine.scanAsync(engine.fromResponseReceived(responseReceived), toolType);
            }
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }
}
