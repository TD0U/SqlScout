package burp.xiasql;

import burp.api.montoya.persistence.PersistedObject;

public final class SettingsRepository {
    private static final String KEY_ENABLED = "enabled";
    private static final String KEY_MONITOR_REPEATER = "monitorRepeater";
    private static final String KEY_MONITOR_PROXY = "monitorProxy";
    private static final String KEY_NUMERIC_DELTA = "numericDeltaPayloads";
    private static final String KEY_TEST_COOKIE = "testCookieParameters";
    private static final String KEY_CUSTOM_PAYLOADS = "customPayloadsEnabled";
    private static final String KEY_ENCODE_SPACES = "encodeSpacesInCustomPayloads";
    private static final String KEY_BLANK_VALUES = "blankValueForCustomPayloads";
    private static final String KEY_WHITELIST_ENABLED = "whitelistEnabled";
    private static final String KEY_WHITELIST_TEXT = "whitelistText";
    private static final String KEY_BLACKLIST_ENABLED = "blacklistEnabled";
    private static final String KEY_BLACKLIST_TEXT = "blacklistText";
    private static final String KEY_SUFFIX_FILTER_ENABLED = "suffixFilterEnabled";
    private static final String KEY_SUFFIX_FILTER_TEXT = "suffixFilterText";
    private static final String KEY_HIDDEN_PARAMETER_TEXT = "hiddenParameterText";
    private static final String KEY_PAYLOAD_GROUP_MODE = "payloadGroupMode";
    private static final String KEY_CUSTOM_PAYLOAD_TEXT = "customPayloadText";
    private static final String KEY_ERROR_PATTERN_TEXT = "errorPatternText";

    private final PersistedObject persistedObject;

    public SettingsRepository(PersistedObject persistedObject) {
        this.persistedObject = persistedObject;
    }

    public void loadInto(ExtensionState state) {
        Boolean enabled = persistedObject.getBoolean(KEY_ENABLED);
        if (enabled != null) {
            state.enabled(enabled.booleanValue());
        }

        Boolean monitorRepeater = persistedObject.getBoolean(KEY_MONITOR_REPEATER);
        if (monitorRepeater != null) {
            state.monitorRepeater(monitorRepeater.booleanValue());
        }

        Boolean monitorProxy = persistedObject.getBoolean(KEY_MONITOR_PROXY);
        if (monitorProxy != null) {
            state.monitorProxy(monitorProxy.booleanValue());
        }

        Boolean numericDelta = persistedObject.getBoolean(KEY_NUMERIC_DELTA);
        if (numericDelta != null) {
            state.numericDeltaPayloads(numericDelta.booleanValue());
        }

        Boolean testCookie = persistedObject.getBoolean(KEY_TEST_COOKIE);
        if (testCookie != null) {
            state.testCookieParameters(testCookie.booleanValue());
        }

        Boolean customPayloads = persistedObject.getBoolean(KEY_CUSTOM_PAYLOADS);
        if (customPayloads != null) {
            state.customPayloadsEnabled(customPayloads.booleanValue());
        }

        Boolean encodeSpaces = persistedObject.getBoolean(KEY_ENCODE_SPACES);
        if (encodeSpaces != null) {
            state.encodeSpacesInCustomPayloads(encodeSpaces.booleanValue());
        }

        Boolean blankValues = persistedObject.getBoolean(KEY_BLANK_VALUES);
        if (blankValues != null) {
            state.blankValueForCustomPayloads(blankValues.booleanValue());
        }

        Boolean whitelistEnabled = persistedObject.getBoolean(KEY_WHITELIST_ENABLED);
        if (whitelistEnabled != null) {
            state.whitelistEnabled(whitelistEnabled.booleanValue());
        }

        String whitelistText = persistedObject.getString(KEY_WHITELIST_TEXT);
        if (whitelistText != null) {
            state.whitelistText(whitelistText);
        }

        Boolean blacklistEnabled = persistedObject.getBoolean(KEY_BLACKLIST_ENABLED);
        if (blacklistEnabled != null) {
            state.blacklistEnabled(blacklistEnabled.booleanValue());
        }

        String blacklistText = persistedObject.getString(KEY_BLACKLIST_TEXT);
        if (blacklistText != null) {
            state.blacklistText(blacklistText);
        }

        Boolean suffixFilterEnabled = persistedObject.getBoolean(KEY_SUFFIX_FILTER_ENABLED);
        if (suffixFilterEnabled != null) {
            state.suffixFilterEnabled(suffixFilterEnabled.booleanValue());
        }

        String suffixFilterText = persistedObject.getString(KEY_SUFFIX_FILTER_TEXT);
        if (suffixFilterText != null) {
            state.suffixFilterText(suffixFilterText);
        }

        String hiddenParameterText = persistedObject.getString(KEY_HIDDEN_PARAMETER_TEXT);
        if (hiddenParameterText != null) {
            state.hiddenParameterText(hiddenParameterText);
        }

        String payloadGroupMode = persistedObject.getString(KEY_PAYLOAD_GROUP_MODE);
        if (payloadGroupMode != null) {
            state.payloadGroupMode(PayloadGroupMode.fromId(payloadGroupMode));
        }

        String customPayloadText = persistedObject.getString(KEY_CUSTOM_PAYLOAD_TEXT);
        if (customPayloadText != null) {
            state.customPayloadText(customPayloadText);
        }

        String errorPatternText = persistedObject.getString(KEY_ERROR_PATTERN_TEXT);
        if (errorPatternText != null) {
            state.errorPatternText(errorPatternText);
        }
    }

    public void save(ExtensionState state) {
        persistedObject.setBoolean(KEY_ENABLED, state.enabled());
        persistedObject.setBoolean(KEY_MONITOR_REPEATER, state.monitorRepeater());
        persistedObject.setBoolean(KEY_MONITOR_PROXY, state.monitorProxy());
        persistedObject.setBoolean(KEY_NUMERIC_DELTA, state.numericDeltaPayloads());
        persistedObject.setBoolean(KEY_TEST_COOKIE, state.testCookieParameters());
        persistedObject.setBoolean(KEY_CUSTOM_PAYLOADS, state.customPayloadsEnabled());
        persistedObject.setBoolean(KEY_ENCODE_SPACES, state.encodeSpacesInCustomPayloads());
        persistedObject.setBoolean(KEY_BLANK_VALUES, state.blankValueForCustomPayloads());
        persistedObject.setBoolean(KEY_WHITELIST_ENABLED, state.whitelistEnabled());
        persistedObject.setString(KEY_WHITELIST_TEXT, state.whitelistText());
        persistedObject.setBoolean(KEY_BLACKLIST_ENABLED, state.blacklistEnabled());
        persistedObject.setString(KEY_BLACKLIST_TEXT, state.blacklistText());
        persistedObject.setBoolean(KEY_SUFFIX_FILTER_ENABLED, state.suffixFilterEnabled());
        persistedObject.setString(KEY_SUFFIX_FILTER_TEXT, state.suffixFilterText());
        persistedObject.setString(KEY_HIDDEN_PARAMETER_TEXT, state.hiddenParameterText());
        persistedObject.setString(KEY_PAYLOAD_GROUP_MODE, state.payloadGroupMode().id());
        persistedObject.setString(KEY_CUSTOM_PAYLOAD_TEXT, state.customPayloadText());
        persistedObject.setString(KEY_ERROR_PATTERN_TEXT, state.errorPatternText());
    }
}
