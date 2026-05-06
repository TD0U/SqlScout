package burp.xiasql;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import java.awt.Component;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Arrays;
import javax.swing.JMenuItem;

public final class XiaSqlContextMenuProvider implements ContextMenuItemsProvider {
    private final DetectionEngine engine;
    private final ExtensionState state;

    public XiaSqlContextMenuProvider(DetectionEngine engine, ExtensionState state) {
        this.engine = engine;
        this.state = state;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        ToolType toolType = event.toolType();
        if (toolType != ToolType.REPEATER && toolType != ToolType.PROXY) {
            return Collections.emptyList();
        }

        List<HttpRequestResponse> targets = new ArrayList<HttpRequestResponse>(event.selectedRequestResponses());
        if (targets.isEmpty() && event.messageEditorRequestResponse().isPresent()) {
            targets.add(event.messageEditorRequestResponse().get().requestResponse());
        }
        if (targets.isEmpty()) {
            return Collections.emptyList();
        }

        JMenuItem item = new JMenuItem("Send to SqlScout");
        item.addActionListener(e -> {
            if (state.enabled()) {
                for (HttpRequestResponse requestResponse : targets) {
                    engine.scanAsync(requestResponse, ToolType.EXTENSIONS);
                }
            }
        });
        return Arrays.<Component>asList(item);
    }
}
