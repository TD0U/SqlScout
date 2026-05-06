package burp.xiasql;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;

public final class ScanLogEntry {
    private String state;
    private final int id;
    private final ToolType toolType;
    private final HttpRequestResponse requestResponse;
    private final String url;
    private final String parameter;
    private final String payloadValue;
    private final String change;
    private final String fingerprint;
    private final long durationMillis;
    private final short statusCode;
    private final String mutatorName;
    private final FindingVerdict verdict;
    private final double similarity;

    public ScanLogEntry(int id, ToolType toolType, HttpRequestResponse requestResponse, String url, String parameter,
            String payloadValue, String change, String fingerprint, long durationMillis, String state, short statusCode,
            String mutatorName, FindingVerdict verdict, double similarity) {
        this.id = id;
        this.toolType = toolType;
        this.requestResponse = requestResponse;
        this.url = url;
        this.parameter = parameter;
        this.payloadValue = payloadValue;
        this.change = change;
        this.fingerprint = fingerprint;
        this.durationMillis = durationMillis;
        this.state = state;
        this.statusCode = statusCode;
        this.mutatorName = mutatorName;
        this.verdict = verdict;
        this.similarity = similarity;
    }

    public int id() {
        return id;
    }

    public ToolType toolType() {
        return toolType;
    }

    public HttpRequestResponse requestResponse() {
        return requestResponse;
    }

    public String url() {
        return url;
    }

    public String parameter() {
        return parameter;
    }

    public String payloadValue() {
        return payloadValue;
    }

    public String change() {
        return change;
    }

    public String fingerprint() {
        return fingerprint;
    }

    public long durationMillis() {
        return durationMillis;
    }

    public short statusCode() {
        return statusCode;
    }

    public String mutatorName() {
        return mutatorName;
    }

    public FindingVerdict verdict() {
        return verdict;
    }

    public double similarity() {
        return similarity;
    }

    public String state() {
        return state;
    }

    public void state(String state) {
        this.state = state;
    }

    public int responseLength() {
        if (requestResponse == null || requestResponse.response() == null) {
            return 0;
        }
        return requestResponse.response().toByteArray().length();
    }
}
