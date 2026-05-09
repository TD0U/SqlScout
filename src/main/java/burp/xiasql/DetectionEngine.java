package burp.xiasql;

import static burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public final class DetectionEngine {
    private final MontoyaApi api;
    private final ExtensionState state;
    private final ScanLogStore logStore;
    private final RequestMutationService mutationService;
    private final ResponseComparator responseComparator;
    private final ThreadPoolExecutor executor;

    public DetectionEngine(MontoyaApi api, ExtensionState state, ScanLogStore logStore) {
        this.api = api;
        this.state = state;
        this.logStore = logStore;
        this.mutationService = new RequestMutationService(new JsonParameterMutator(), new StandardParameterMutator());
        this.responseComparator = new ResponseComparator();
        int threads = state.concurrentScans();
        this.executor = new ThreadPoolExecutor(threads, threads, 60L, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
    }

    public void updateConcurrentScans(int size) {
        int n = Math.max(1, Math.min(20, size));
        executor.setCorePoolSize(n);
        executor.setMaximumPoolSize(n);
    }

    public void scanAsync(HttpRequestResponse requestResponse, ToolType source) {
        executor.submit(() -> scan(requestResponse, source));
    }

    public void shutdown() {
        executor.shutdownNow();
        try {
            executor.awaitTermination(3, TimeUnit.SECONDS);
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
        }
    }

    public void scan(HttpRequestResponse requestResponse, ToolType source) {
        try {
            if (!shouldScan(requestResponse)) {
                return;
            }

            HttpRequest request = requestResponse.request();
            List<ParsedHttpParameter> parameters = injectableParameters(request);
            List<EncodedJsonParameterPoint> encodedJsonPoints = encodedJsonPoints(request, parameters);
            List<HiddenParameterPoint> hiddenParameterPoints = hiddenParameterPoints(request);
            if (parameters.isEmpty() && encodedJsonPoints.isEmpty() && hiddenParameterPoints.isEmpty()) {
                return;
            }

            String fingerprint = fingerprint(request, parameters);
            if (!logStore.rememberFingerprint(fingerprint) && source != ToolType.EXTENSIONS) {
                return;
            }

            int id = logStore.nextId();
            int originalLength = responseLength(requestResponse.response());
            ScanLogEntry parent = new ScanLogEntry(id, source, requestResponse.copyToTempFile(), request.url(), "", "", "", fingerprint, 0, "run...", statusCode(requestResponse.response()), "", FindingVerdict.INFO, 1.0);
            logStore.addScan(parent);

            FindingVerdict overallVerdict = FindingVerdict.INFO;
            int suspiciousAttempts = 0;
            for (ParsedHttpParameter parameter : parameters) {
                ParameterProfile profile = ParameterClassifier.classify(parameter);
                int firstProbeLength = 0;
                for (String payload : payloads(profile)) {
                    String baseValue = state.blankValueForCustomPayloads() && isCustomPayload(payload) ? "" : profile.baseValue();
                    String mutatedValue = baseValue + payload;
                    RequestMutation mutation = mutationService.mutate(request, parameter, mutatedValue);
                    if (mutation == null) {
                        continue;
                    }

                    long start = System.nanoTime();
                    HttpRequestResponse mutated = api.http().sendRequest(mutation.request());
                    long durationMillis = (System.nanoTime() - start) / 1_000_000L;
                    sleepIfNeeded();

                    HttpResponse response = mutated.response();
                    int currentLength = responseLength(response);
                    String baselineBody = firstProbeLength == 0 ? requestResponse.response().bodyToString() : null;
                    AttemptAnalysis analysis = analyzeAttempt(payload, firstProbeLength, currentLength, originalLength, durationMillis, baselineBody, response);
                    if (firstProbeLength == 0 && ("'".equals(payload) || "-1".equals(payload))) {
                        firstProbeLength = currentLength;
                    }
                    if (analysis.verdict() != FindingVerdict.INFO) {
                        suspiciousAttempts++;
                    }
                    overallVerdict = FindingVerdict.max(overallVerdict, analysis.verdict());
                    String matchedPattern = firstMatchingErrorPattern(response);
                    if (!matchedPattern.trim().isEmpty()) {
                        state.addUiLog(id + " -> diy_error: " + matchedPattern);
                    }

                    HttpRequestResponse highlightedResponse = applyHighlight(mutated, mutation);
                    ScanLogEntry attempt = new ScanLogEntry(id, source, highlightedResponse.copyToTempFile(), mutation.request().url(), mutation.parameterName(), mutatedValue,
                            analysis.changeSummary(), fingerprint, durationMillis, analysis.verdict().code(), statusCode(response), mutation.mutatorName(),
                            analysis.verdict(), analysis.similarity());
                    logStore.addAttempt(attempt);
                    updateRunningScanRow(parent, overallVerdict, suspiciousAttempts, analysis.signals());
                }
            }

            for (EncodedJsonParameterPoint point : encodedJsonPoints) {
                ParameterProfile profile = point.profile();
                int firstProbeLength = 0;
                for (String payload : payloads(profile)) {
                    String baseValue = state.blankValueForCustomPayloads() && isCustomPayload(payload) ? "" : profile.baseValue();
                    String mutatedValue = baseValue + payload;
                    RequestMutation mutation = point.mutate(mutatedValue);
                    if (mutation == null) {
                        continue;
                    }

                    long start = System.nanoTime();
                    HttpRequestResponse mutated = api.http().sendRequest(mutation.request());
                    long durationMillis = (System.nanoTime() - start) / 1_000_000L;
                    sleepIfNeeded();

                    HttpResponse response = mutated.response();
                    int currentLength = responseLength(response);
                    String baselineBody = firstProbeLength == 0 ? requestResponse.response().bodyToString() : null;
                    AttemptAnalysis analysis = analyzeAttempt(payload, firstProbeLength, currentLength, originalLength, durationMillis, baselineBody, response);
                    if (firstProbeLength == 0 && ("'".equals(payload) || "-1".equals(payload))) {
                        firstProbeLength = currentLength;
                    }
                    if (analysis.verdict() != FindingVerdict.INFO) {
                        suspiciousAttempts++;
                    }
                    overallVerdict = FindingVerdict.max(overallVerdict, analysis.verdict());
                    String matchedPattern = firstMatchingErrorPattern(response);
                    if (!matchedPattern.trim().isEmpty()) {
                        state.addUiLog(id + " -> diy_error: " + matchedPattern);
                    }

                    HttpRequestResponse highlightedResponse = applyHighlight(mutated, mutation);
                    ScanLogEntry attempt = new ScanLogEntry(id, source, highlightedResponse.copyToTempFile(), mutation.request().url(), mutation.parameterName(), mutatedValue,
                            analysis.changeSummary(), fingerprint, durationMillis, analysis.verdict().code(), statusCode(response), mutation.mutatorName(),
                            analysis.verdict(), analysis.similarity());
                    logStore.addAttempt(attempt);
                    updateRunningScanRow(parent, overallVerdict, suspiciousAttempts, analysis.signals());
                }
            }

            for (HiddenParameterPoint point : hiddenParameterPoints) {
                ParameterProfile profile = point.profile();
                int firstProbeLength = 0;
                for (String payload : payloads(profile)) {
                    String baseValue = state.blankValueForCustomPayloads() && isCustomPayload(payload) ? "" : profile.baseValue();
                    String mutatedValue = baseValue + payload;
                    RequestMutation mutation = point.mutate(mutatedValue);
                    if (mutation == null) {
                        continue;
                    }

                    long start = System.nanoTime();
                    HttpRequestResponse mutated = api.http().sendRequest(mutation.request());
                    long durationMillis = (System.nanoTime() - start) / 1_000_000L;
                    sleepIfNeeded();

                    HttpResponse response = mutated.response();
                    int currentLength = responseLength(response);
                    String baselineBody = firstProbeLength == 0 ? requestResponse.response().bodyToString() : null;
                    AttemptAnalysis analysis = analyzeAttempt(payload, firstProbeLength, currentLength, originalLength, durationMillis, baselineBody, response);
                    if (firstProbeLength == 0 && ("'".equals(payload) || "-1".equals(payload))) {
                        firstProbeLength = currentLength;
                    }
                    if (analysis.verdict() != FindingVerdict.INFO) {
                        suspiciousAttempts++;
                    }
                    overallVerdict = FindingVerdict.max(overallVerdict, analysis.verdict());
                    String matchedPattern = firstMatchingErrorPattern(response);
                    if (!matchedPattern.trim().isEmpty()) {
                        state.addUiLog(id + " -> diy_error: " + matchedPattern);
                    }

                    HttpRequestResponse highlightedResponse = applyHighlight(mutated, mutation);
                    ScanLogEntry attempt = new ScanLogEntry(id, source, highlightedResponse.copyToTempFile(), mutation.request().url(), mutation.parameterName(), mutatedValue,
                            analysis.changeSummary(), fingerprint, durationMillis, analysis.verdict().code(), statusCode(response), mutation.mutatorName(),
                            analysis.verdict(), analysis.similarity());
                    logStore.addAttempt(attempt);
                    updateRunningScanRow(parent, overallVerdict, suspiciousAttempts, analysis.signals());
                }
            }

            String stateText = buildParentState(overallVerdict, suspiciousAttempts);
            parent.state(stateText);
            parent = new ScanLogEntry(parent.id(), parent.toolType(), parent.requestResponse(), parent.url(), parent.parameter(), parent.payloadValue(),
                    parent.change(), parent.fingerprint(), parent.durationMillis(), stateText, parent.statusCode(), parent.mutatorName(), overallVerdict, parent.similarity());
            replaceScan(parent);
        } catch (Exception ex) {
            api.logging().logToError("SqlScout scan failed: " + ex.getMessage());
        }
    }

    private boolean shouldScan(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.request() == null || !requestResponse.hasResponse()) {
            return false;
        }
        HttpRequest request = requestResponse.request();
        String extension = request.fileExtension();
        if (state.suffixFilterEnabled() && extension != null && configuredSuffixFilters().contains(extension.toLowerCase(Locale.ROOT))) {
            return false;
        }
        if (state.blacklistEnabled() && isBlacklisted(request.url())) {
            return false;
        }
        if (state.whitelistEnabled() && !isWhitelisted(request.url())) {
            return false;
        }
        HttpResponse response = requestResponse.response();
        return response != null && !looksLikeImage(response.body().getBytes());
    }

    private java.util.Set<String> configuredSuffixFilters() {
        java.util.Set<String> suffixes = new HashSet<String>();
        for (String token : state.suffixFilterText().split(",")) {
            String trimmed = token.trim().toLowerCase(Locale.ROOT);
            if (trimmed.startsWith(".")) {
                trimmed = trimmed.substring(1);
            }
            if (!trimmed.isEmpty()) {
                suffixes.add(trimmed);
            }
        }
        return suffixes;
    }

    private boolean isWhitelisted(String url) {
        String whitelistText = state.whitelistText().trim();
        if (whitelistText.isEmpty()) {
            return false;
        }
        for (String token : whitelistText.split(",")) {
            String trimmed = token.trim();
            if (!trimmed.isEmpty() && wildcardMatch(url, trimmed)) {
                return true;
            }
        }
        return false;
    }

    private boolean isBlacklisted(String url) {
        String blacklistText = state.blacklistText().trim();
        if (blacklistText.isEmpty()) {
            return false;
        }
        for (String token : blacklistText.split(",")) {
            String trimmed = token.trim();
            if (!trimmed.isEmpty() && wildcardMatch(url, trimmed)) {
                return true;
            }
        }
        return false;
    }

    private static boolean wildcardMatch(String text, String pattern) {
        String regex = "(?i)" + Pattern.quote(pattern).replace("\\*", "\\E.*\\Q");
        return Pattern.matches(regex, text);
    }

    private List<ParsedHttpParameter> injectableParameters(HttpRequest request) {
        List<ParsedHttpParameter> parameters = new ArrayList<>();
        for (ParsedHttpParameter parameter : request.parameters()) {
            HttpParameterType type = parameter.type();
            if (type == HttpParameterType.URL
                    || type == HttpParameterType.BODY
                    || type == HttpParameterType.JSON
                    || type == HttpParameterType.MULTIPART_ATTRIBUTE
                    || (state.testCookieParameters() && type == HttpParameterType.COOKIE)) {
                if (MultipartParameterHeuristics.shouldSkip(request, parameter)) {
                    continue;
                }
                parameters.add(parameter);
            }
        }
        return parameters;
    }

    private List<EncodedJsonParameterPoint> encodedJsonPoints(HttpRequest request, List<ParsedHttpParameter> parameters) {
        List<EncodedJsonParameterPoint> points = new ArrayList<EncodedJsonParameterPoint>();
        for (ParsedHttpParameter parameter : parameters) {
            if (parameter.type() != HttpParameterType.URL && parameter.type() != HttpParameterType.BODY) {
                continue;
            }
            String decoded = EncodedJsonParameterPoint.decodeIfJsonLike(parameter.value());
            if (decoded == null) {
                continue;
            }
            for (JsonLeaf leaf : JsonLeafCollector.collect(decoded)) {
                points.add(new EncodedJsonParameterPoint(request, parameter, leaf, decoded));
            }
        }
        return points;
    }

    private List<HiddenParameterPoint> hiddenParameterPoints(HttpRequest request) {
        List<HiddenParameterPoint> points = new ArrayList<HiddenParameterPoint>();
        if (request.contentType() == burp.api.montoya.http.message.ContentType.JSON) {
            return points;
        }

        Set<String> existingNames = new HashSet<String>();
        for (ParsedHttpParameter parameter : request.parameters()) {
            existingNames.add(parameter.name().toLowerCase(Locale.ROOT));
        }

        for (String token : state.hiddenParameterText().split("\\R|,")) {
            String name = token.trim();
            if (name.isEmpty()) {
                continue;
            }
            if (existingNames.contains(name.toLowerCase(Locale.ROOT))) {
                continue;
            }
            HttpParameterType parameterType = request.method().equalsIgnoreCase("GET") ? HttpParameterType.URL : HttpParameterType.BODY;
            points.add(new HiddenParameterPoint(request, name, parameterType));
        }
        return points;
    }

    private List<String> payloads(ParameterProfile profile) {
        PayloadGroupMode mode = effectivePayloadGroup(profile);
        List<String> payloads = new ArrayList<>();
        if (mode == PayloadGroupMode.ORDER) {
            payloads.add("'");
            payloads.add("''");
            payloads.add(" desc'");
            payloads.add(" asc'");
            payloads.add(" desc--");
        } else if (mode == PayloadGroupMode.TIME) {
            payloads.add("%df' and sleep(3)%23");
            payloads.add("' AND sleep(5)");
            payloads.add("'||pg_sleep(5)||'");
        } else if (mode == PayloadGroupMode.ERROR) {
            payloads.add("'");
            payloads.add("\"");
            payloads.add("%df'");
        } else if (mode == PayloadGroupMode.CUSTOM || state.customPayloadsEnabled()) {
            for (String line : state.customPayloadText().split("\\R")) {
                if (!line.trim().isEmpty()) {
                    payloads.add(state.encodeSpacesInCustomPayloads() ? line.replace(" ", "%20") : line);
                }
            }
        } else {
            payloads.add("'");
            payloads.add("''");
        }
        if (state.numericDeltaPayloads() && profile.numeric()) {
            payloads.add("-1");
            payloads.add("-0");
        }
        return payloads;
    }

    private PayloadGroupMode effectivePayloadGroup(ParameterProfile profile) {
        PayloadGroupMode configured = state.payloadGroupMode();
        if (configured != PayloadGroupMode.AUTO) {
            return configured;
        }
        if (profile.category() == ParameterProfile.Category.SORT_CONTROL) {
            return PayloadGroupMode.ORDER;
        }
        if (profile.numeric()) {
            return PayloadGroupMode.DEFAULT;
        }
        return state.customPayloadsEnabled() ? PayloadGroupMode.CUSTOM : PayloadGroupMode.DEFAULT;
    }

    private boolean isCustomPayload(String payload) {
        return !"'".equals(payload) && !"''".equals(payload) && !"-1".equals(payload) && !"-0".equals(payload);
    }

    private AttemptAnalysis analyzeAttempt(String payload, int firstProbeLength, int currentLength, int originalLength, long durationMillis, String baselineBody, HttpResponse response) {
        EnumSet<AttemptSignal> signals = EnumSet.noneOf(AttemptSignal.class);
        ResponseComparisonResult comparison = responseComparator.compare(
                baselineBody == null ? "" : baselineBody,
                response == null ? "" : response.bodyToString(),
                originalLength,
                firstProbeLength == 0 ? originalLength : firstProbeLength,
                currentLength);
        String change = classifyChange(payload, comparison, durationMillis, signals);
        String matchedPattern = firstMatchingErrorPattern(response);
        if (!matchedPattern.trim().isEmpty()) {
            signals.add(AttemptSignal.ERROR_PATTERN);
            change = (change + " Err").trim();
        }
        FindingVerdict verdict = verdictFor(signals);
        return new AttemptAnalysis(change, signals, verdict, comparison.similarity());
    }

    private String classifyChange(String payload, ResponseComparisonResult comparison, long durationMillis, Set<AttemptSignal> signals) {
        if ("'".equals(payload) || "-1".equals(payload) || comparison.baselineLength() == comparison.originalLength() && comparison.currentLength() == comparison.originalLength()) {
            return "";
        }
        if ("''".equals(payload) || "-0".equals(payload)) {
            if (comparison.similarity() < 0.98 || comparison.baselineDelta() != 0) {
                signals.add(AttemptSignal.LENGTH_DELTA);
                if (comparison.currentLength() == comparison.originalLength()) {
                    return "✔ ==> ?";
                }
                return "✔ " + comparison.baselineDelta();
            }
            return "";
        }
        if (durationMillis >= 3000) {
            signals.add(AttemptSignal.TIME_DELAY);
            return "time > 3";
        }
        if (isCustomPayload(payload)) {
            signals.add(AttemptSignal.CUSTOM_PAYLOAD);
        }
        if (comparison.similarity() < 0.95) {
            signals.add(AttemptSignal.LENGTH_DELTA);
            return "diff sim=" + String.format("%.2f", comparison.similarity());
        }
        return "diy payload";
    }

    private FindingVerdict verdictFor(Set<AttemptSignal> signals) {
        if (signals.contains(AttemptSignal.ERROR_PATTERN)) {
            return FindingVerdict.CONFIRMED;
        }
        if (signals.contains(AttemptSignal.TIME_DELAY) || signals.contains(AttemptSignal.LENGTH_DELTA) || signals.contains(AttemptSignal.ERROR_PATTERN)) {
            return FindingVerdict.SUSPECTED;
        }
        return FindingVerdict.INFO;
    }

    private String buildParentState(FindingVerdict verdict, int suspiciousAttempts) {
        if (verdict == FindingVerdict.CONFIRMED) {
            return "end! " + verdict.displayName() + " (" + suspiciousAttempts + ")";
        }
        if (verdict == FindingVerdict.SUSPECTED) {
            return "end! " + verdict.displayName() + " (" + suspiciousAttempts + ")";
        }
        return "end! " + verdict.displayName();
    }

    private void updateRunningScanRow(ScanLogEntry parent, FindingVerdict verdict, int suspiciousAttempts, Set<AttemptSignal> signals) {
        String stateText = buildRunningState(verdict, suspiciousAttempts, signals);
        ScanLogEntry runningEntry = new ScanLogEntry(
                parent.id(),
                parent.toolType(),
                parent.requestResponse(),
                parent.url(),
                parent.parameter(),
                parent.payloadValue(),
                parent.change(),
                parent.fingerprint(),
                parent.durationMillis(),
                stateText,
                parent.statusCode(),
                parent.mutatorName(),
                verdict,
                parent.similarity());
        replaceScan(runningEntry);
    }

    private String buildRunningState(FindingVerdict verdict, int suspiciousAttempts, Set<AttemptSignal> signals) {
        List<String> markers = new ArrayList<String>();
        if (signals.contains(AttemptSignal.ERROR_PATTERN)) {
            markers.add("Err");
        }
        if (signals.contains(AttemptSignal.TIME_DELAY)) {
            markers.add("Time");
        }
        if (signals.contains(AttemptSignal.LENGTH_DELTA)) {
            markers.add("Diff");
        }
        String markerText = markers.isEmpty() ? "" : " [" + String.join("/", markers) + "]";
        if (suspiciousAttempts > 0) {
            return "run... " + verdict.displayName() + " (" + suspiciousAttempts + ")" + markerText;
        }
        return "run..." + markerText;
    }

    private void replaceScan(ScanLogEntry replacement) {
        logStore.replaceScan(replacement);
    }

    private void sleepIfNeeded() {
        int delay = state.requestDelayMs();
        if (delay > 0) {
            try {
                Thread.sleep(delay);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }


    private HttpRequestResponse applyHighlight(HttpRequestResponse response, RequestMutation mutation) {
        if (response == null || mutation == null || !mutation.hasHighlight()) {
            return response;
        }
        return httpRequestResponse(
                response.request().withMarkers(Marker.marker(mutation.highlightStart(), mutation.highlightEnd())),
                response.response(),
                response.annotations());
    }

    private String firstMatchingErrorPattern(HttpResponse response) {
        if (response == null) {
            return "";
        }
        String body = response.bodyToString();
        for (String patternText : state.errorPatternText().split("\\R")) {
            if (patternText.trim().isEmpty()) {
                continue;
            }
            try {
                if (Pattern.compile(patternText).matcher(body).find()) {
                    return patternText;
                }
            } catch (PatternSyntaxException ignored) {
                if (body.contains(patternText)) {
                    return patternText;
                }
            }
        }
        return "";
    }

    private String fingerprint(HttpRequest request, List<ParsedHttpParameter> parameters) {
        StringBuilder data = new StringBuilder(request.url().split("\\?")[0]);
        for (ParsedHttpParameter parameter : parameters) {
            data.append('+').append(parameter.name());
        }
        data.append('+').append(request.method());
        return md5(data.toString());
    }

    private static String md5(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            return toHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return Integer.toHexString(value.hashCode()).toUpperCase(Locale.ROOT);
        }
    }

    private static String toHex(byte[] bytes) {
        char[] hex = "0123456789ABCDEF".toCharArray();
        char[] output = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xff;
            output[i * 2] = hex[value >>> 4];
            output[i * 2 + 1] = hex[value & 0x0f];
        }
        return new String(output);
    }

    private static boolean looksLikeImage(byte[] body) {
        if (body.length >= 2 && (body[0] & 0xff) == 0xff && (body[1] & 0xff) == 0xd8) {
            return true;
        }
        if (body.length >= 4 && (body[0] & 0xff) == 0x89 && body[1] == 0x50 && body[2] == 0x4e && body[3] == 0x47) {
            return true;
        }
        return body.length >= 2 && body[0] == 0x47 && body[1] == 0x49;
    }

    private static int responseLength(HttpResponse response) {
        return response == null ? 0 : response.toByteArray().length();
    }

    private static short statusCode(HttpResponse response) {
        return response == null ? -1 : response.statusCode();
    }

    public HttpRequestResponse fromResponseReceived(burp.api.montoya.http.handler.HttpResponseReceived responseReceived) {
        return httpRequestResponse(responseReceived.initiatingRequest(), responseReceived);
    }
}
