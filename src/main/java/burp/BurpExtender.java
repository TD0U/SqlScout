package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.xiasql.DetectionEngine;
import burp.xiasql.ExtensionState;
import burp.xiasql.ScanLogStore;
import burp.xiasql.SettingsRepository;
import burp.xiasql.XiaSqlContextMenuProvider;
import burp.xiasql.XiaSqlHttpHandler;
import burp.xiasql.XiaSqlPanel;

public final class BurpExtender implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("SqlScout");

        ExtensionState state = new ExtensionState();
        SettingsRepository settingsRepository = new SettingsRepository(api.persistence().extensionData());
        settingsRepository.loadInto(state);
        state.addListener(() -> settingsRepository.save(state));
        ScanLogStore logStore = new ScanLogStore();
        DetectionEngine engine = new DetectionEngine(api, state, logStore);
        XiaSqlPanel panel = new XiaSqlPanel(api, state, logStore, engine);

        api.userInterface().registerSuiteTab("SqlScout", panel.component());
        api.http().registerHttpHandler(new XiaSqlHttpHandler(engine, state));
        api.userInterface().registerContextMenuItemsProvider(new XiaSqlContextMenuProvider(engine, state));
        api.extension().registerUnloadingHandler(engine::shutdown);

        api.logging().logToOutput("SqlScout loaded with Montoya API 2026.4");
    }
}
