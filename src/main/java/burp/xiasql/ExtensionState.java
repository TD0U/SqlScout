package burp.xiasql;

import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.CopyOnWriteArrayList;

public final class ExtensionState {
    public interface Listener {
        void stateChanged();
    }

    public static final String DEFAULT_PAYLOADS = "%df' and sleep(3)%23\n'and '1'='1";
    public static final String DEFAULT_ERROR_PATTERNS = String.join("\n",
            "ORA-\\d{5}",
            "SQL syntax.*?MySQL",
            "Unknown column",
            "SQL syntax",
            "java.sql.SQLSyntaxErrorException",
            "Error SQL:",
            "Syntax error",
            "附近有语法错误",
            "java.sql.SQLException",
            "引号不完整",
            "System.Exception: SQL Execution Error!",
            "com.mysql.jdbc",
            "MySQLSyntaxErrorException",
            "valid MySQL result",
            "your MySQL server version",
            "MySqlClient",
            "MySqlException",
            "valid PostgreSQL result",
            "PG::SyntaxError:",
            "org.postgresql.jdbc",
            "PSQLException",
            "Microsoft SQL Native Client error",
            "ODBC SQL Server Driver",
            "SQLServer JDBC Driver",
            "com.jnetdirect.jsql",
            "macromedia.jdbc.sqlserver",
            "com.microsoft.sqlserver.jdbc",
            "Microsoft Access",
            "Access Database Engine",
            "ODBC Microsoft Access",
            "Oracle error",
            "DB2 SQL error",
            "SQLite error",
            "Sybase message",
            "SybSQLException");
    public static final String DEFAULT_SUFFIX_FILTERS = "jpg,jpeg,png,gif,css,js,pdf,mp3,mp4,avi,svg,woff,woff2,ico";

    private volatile boolean enabled = true;
    private volatile boolean monitorRepeater;
    private volatile boolean monitorProxy;
    private volatile boolean numericDeltaPayloads = true;
    private volatile boolean testCookieParameters;
    private volatile boolean customPayloadsEnabled;
    private volatile boolean encodeSpacesInCustomPayloads = true;
    private volatile boolean blankValueForCustomPayloads;
    private volatile boolean whitelistEnabled;
    private volatile String whitelistText = "";
    private volatile boolean blacklistEnabled;
    private volatile String blacklistText = "";
    private volatile boolean suffixFilterEnabled = true;
    private volatile String suffixFilterText = DEFAULT_SUFFIX_FILTERS;
    private volatile String hiddenParameterText = "";
    private volatile PayloadGroupMode payloadGroupMode = PayloadGroupMode.AUTO;
    private volatile String customPayloadText = DEFAULT_PAYLOADS;
    private volatile String errorPatternText = DEFAULT_ERROR_PATTERNS;
    private volatile int concurrentScans = 4;
    private volatile int requestDelayMs = 0;
    private final List<String> uiLog = new CopyOnWriteArrayList<>();
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();

    public boolean enabled() {
        return enabled;
    }

    public void enabled(boolean enabled) {
        this.enabled = enabled;
        notifyListeners();
    }

    public boolean monitorRepeater() {
        return monitorRepeater;
    }

    public void monitorRepeater(boolean monitorRepeater) {
        this.monitorRepeater = monitorRepeater;
        notifyListeners();
    }

    public boolean monitorProxy() {
        return monitorProxy;
    }

    public void monitorProxy(boolean monitorProxy) {
        this.monitorProxy = monitorProxy;
        notifyListeners();
    }

    public boolean numericDeltaPayloads() {
        return numericDeltaPayloads;
    }

    public void numericDeltaPayloads(boolean numericDeltaPayloads) {
        this.numericDeltaPayloads = numericDeltaPayloads;
        notifyListeners();
    }

    public boolean testCookieParameters() {
        return testCookieParameters;
    }

    public void testCookieParameters(boolean testCookieParameters) {
        this.testCookieParameters = testCookieParameters;
        notifyListeners();
    }

    public boolean customPayloadsEnabled() {
        return customPayloadsEnabled;
    }

    public void customPayloadsEnabled(boolean customPayloadsEnabled) {
        this.customPayloadsEnabled = customPayloadsEnabled;
        notifyListeners();
    }

    public boolean encodeSpacesInCustomPayloads() {
        return encodeSpacesInCustomPayloads;
    }

    public void encodeSpacesInCustomPayloads(boolean encodeSpacesInCustomPayloads) {
        this.encodeSpacesInCustomPayloads = encodeSpacesInCustomPayloads;
        notifyListeners();
    }

    public boolean blankValueForCustomPayloads() {
        return blankValueForCustomPayloads;
    }

    public void blankValueForCustomPayloads(boolean blankValueForCustomPayloads) {
        this.blankValueForCustomPayloads = blankValueForCustomPayloads;
        notifyListeners();
    }

    public boolean whitelistEnabled() {
        return whitelistEnabled;
    }

    public void whitelistEnabled(boolean whitelistEnabled) {
        this.whitelistEnabled = whitelistEnabled;
        notifyListeners();
    }

    public String whitelistText() {
        return whitelistText;
    }

    public void whitelistText(String whitelistText) {
        this.whitelistText = whitelistText == null ? "" : whitelistText;
        notifyListeners();
    }

    public String customPayloadText() {
        return customPayloadText;
    }

    public PayloadGroupMode payloadGroupMode() {
        return payloadGroupMode;
    }

    public void payloadGroupMode(PayloadGroupMode payloadGroupMode) {
        this.payloadGroupMode = payloadGroupMode == null ? PayloadGroupMode.AUTO : payloadGroupMode;
        notifyListeners();
    }

    public boolean suffixFilterEnabled() {
        return suffixFilterEnabled;
    }

    public void suffixFilterEnabled(boolean suffixFilterEnabled) {
        this.suffixFilterEnabled = suffixFilterEnabled;
        notifyListeners();
    }

    public String suffixFilterText() {
        return suffixFilterText;
    }

    public void suffixFilterText(String suffixFilterText) {
        this.suffixFilterText = suffixFilterText == null ? "" : suffixFilterText;
        notifyListeners();
    }

    public boolean blacklistEnabled() {
        return blacklistEnabled;
    }

    public String hiddenParameterText() {
        return hiddenParameterText;
    }

    public void hiddenParameterText(String hiddenParameterText) {
        this.hiddenParameterText = hiddenParameterText == null ? "" : hiddenParameterText;
        notifyListeners();
    }

    public void blacklistEnabled(boolean blacklistEnabled) {
        this.blacklistEnabled = blacklistEnabled;
        notifyListeners();
    }

    public String blacklistText() {
        return blacklistText;
    }

    public void blacklistText(String blacklistText) {
        this.blacklistText = blacklistText == null ? "" : blacklistText;
        notifyListeners();
    }

    public void customPayloadText(String customPayloadText) {
        this.customPayloadText = customPayloadText == null ? "" : customPayloadText;
        notifyListeners();
    }

    public String errorPatternText() {
        return errorPatternText;
    }

    public void errorPatternText(String errorPatternText) {
        this.errorPatternText = errorPatternText == null ? "" : errorPatternText;
        notifyListeners();
    }

    public int concurrentScans() {
        return concurrentScans;
    }

    public void concurrentScans(int concurrentScans) {
        this.concurrentScans = Math.max(1, Math.min(20, concurrentScans));
        notifyListeners();
    }

    public int requestDelayMs() {
        return requestDelayMs;
    }

    public void requestDelayMs(int requestDelayMs) {
        this.requestDelayMs = Math.max(0, Math.min(10000, requestDelayMs));
        notifyListeners();
    }

    public void addUiLog(String line) {
        uiLog.add(0, line);
    }

    public List<String> uiLogSnapshot() {
        return new ArrayList<>(uiLog);
    }

    public void clearUiLog() {
        uiLog.clear();
    }

    public void addListener(Listener listener) {
        listeners.add(listener);
    }

    private void notifyListeners() {
        for (Listener listener : listeners) {
            listener.stateChanged();
        }
    }
}
