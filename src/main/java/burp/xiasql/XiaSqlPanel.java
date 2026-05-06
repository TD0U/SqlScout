package burp.xiasql;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import javax.swing.Box;
import javax.swing.BoxLayout;
import java.util.Collections;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;

public final class XiaSqlPanel {
    private final ExtensionState state;
    private final ScanLogStore logStore;
    private final MainTableModel mainTableModel = new MainTableModel();
    private final AttemptTableModel attemptTableModel = new AttemptTableModel();
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JTextArea uiLogArea = new JTextArea();
    private final JPanel root;
    private String selectedFingerprint = "";

    public XiaSqlPanel(MontoyaApi api, ExtensionState state, ScanLogStore logStore, DetectionEngine engine) {
        this.state = state;
        this.logStore = logStore;
        this.requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        this.root = buildUi();
        api.userInterface().applyThemeToComponent(root);
        logStore.addListener(() -> SwingUtilities.invokeLater(this::refreshTables));
    }

    public Component component() {
        return root;
    }

    private JPanel buildUi() {
        JTable mainTable = new JTable(mainTableModel);
        JTable attemptTable = new JTable(attemptTableModel);

        mainTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            int row = mainTable.getSelectedRow();
            if (row >= 0) {
                ScanLogEntry entry = mainTableModel.entryAt(mainTable.convertRowIndexToModel(row));
                selectedFingerprint = entry.fingerprint();
                show(entry.requestResponse());
                attemptTableModel.reload();
            }
        });
        attemptTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            int row = attemptTable.getSelectedRow();
            if (row >= 0) {
                show(attemptTableModel.entryAt(attemptTable.convertRowIndexToModel(row)).requestResponse());
            }
        });

        JTabbedPane editors = new JTabbedPane();
        editors.addTab("Request", requestEditor.uiComponent());
        editors.addTab("Response", responseEditor.uiComponent());

        JSplitPane left = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(mainTable), new JScrollPane(attemptTable));
        left.setResizeWeight(0.48);
        JSplitPane main = new JSplitPane(JSplitPane.VERTICAL_SPLIT, left, editors);
        main.setResizeWeight(0.55);

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, main, buildSettingsPanel());
        splitPane.setResizeWeight(0.78);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(splitPane, BorderLayout.CENTER);
        return panel;
    }

    private Component buildSettingsPanel() {
        JCheckBox enabled = new JCheckBox("启动插件", state.enabled());
        JCheckBox monitorRepeater = new JCheckBox("监控 Repeater", state.monitorRepeater());
        JCheckBox monitorProxy = new JCheckBox("监控 Proxy", state.monitorProxy());
        JCheckBox numeric = new JCheckBox("数字值追加 -1/-0", state.numericDeltaPayloads());
        JCheckBox cookies = new JCheckBox("测试 Cookie", state.testCookieParameters());
        JCheckBox customPayloads = new JCheckBox("自定义 payload", state.customPayloadsEnabled());
        JCheckBox encodeSpaces = new JCheckBox("空格 URL 编码", state.encodeSpacesInCustomPayloads());
        JCheckBox blankValues = new JCheckBox("自定义 payload 参数值置空", state.blankValueForCustomPayloads());
        JTextField whitelist = new JTextField(state.whitelistText());
        JCheckBox whitelistEnabled = new JCheckBox("启用白名单", state.whitelistEnabled());
        JTextField blacklist = new JTextField(state.blacklistText());
        JCheckBox blacklistEnabled = new JCheckBox("启用黑名单", state.blacklistEnabled());
        JTextField suffixFilters = new JTextField(state.suffixFilterText());
        JCheckBox suffixFilterEnabled = new JCheckBox("启用后缀过滤", state.suffixFilterEnabled());
        JTextArea hiddenParams = new JTextArea(state.hiddenParameterText(), 6, 18);
        JComboBox<PayloadGroupMode> payloadGroupMode = new JComboBox<PayloadGroupMode>(PayloadGroupMode.values());
        payloadGroupMode.setSelectedItem(state.payloadGroupMode());
        JTextArea payloadText = new JTextArea(state.customPayloadText(), 6, 18);
        JTextArea errorPatterns = new JTextArea(state.errorPatternText(), 8, 18);
        uiLogArea.setEditable(false);
        whitelist.setEditable(!state.whitelistEnabled());
        blacklist.setEditable(!state.blacklistEnabled());
        suffixFilters.setEditable(!state.suffixFilterEnabled());

        enabled.addActionListener(e -> state.enabled(enabled.isSelected()));
        monitorRepeater.addActionListener(e -> state.monitorRepeater(monitorRepeater.isSelected()));
        monitorProxy.addActionListener(e -> state.monitorProxy(monitorProxy.isSelected()));
        numeric.addActionListener(e -> state.numericDeltaPayloads(numeric.isSelected()));
        cookies.addActionListener(e -> state.testCookieParameters(cookies.isSelected()));
        customPayloads.addActionListener(e -> state.customPayloadsEnabled(customPayloads.isSelected()));
        encodeSpaces.addActionListener(e -> state.encodeSpacesInCustomPayloads(encodeSpaces.isSelected()));
        blankValues.addActionListener(e -> state.blankValueForCustomPayloads(blankValues.isSelected()));
        whitelist.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                state.whitelistText(whitelist.getText());
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                state.whitelistText(whitelist.getText());
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                state.whitelistText(whitelist.getText());
            }
        });
        blacklist.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                state.blacklistText(blacklist.getText());
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                state.blacklistText(blacklist.getText());
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                state.blacklistText(blacklist.getText());
            }
        });
        suffixFilters.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                state.suffixFilterText(suffixFilters.getText());
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                state.suffixFilterText(suffixFilters.getText());
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                state.suffixFilterText(suffixFilters.getText());
            }
        });
        hiddenParams.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                state.hiddenParameterText(hiddenParams.getText());
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                state.hiddenParameterText(hiddenParams.getText());
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                state.hiddenParameterText(hiddenParams.getText());
            }
        });
        whitelistEnabled.addActionListener(e -> {
            state.whitelistText(whitelist.getText());
            state.whitelistEnabled(whitelistEnabled.isSelected());
            whitelist.setEditable(!whitelistEnabled.isSelected());
        });
        blacklistEnabled.addActionListener(e -> {
            state.blacklistText(blacklist.getText());
            state.blacklistEnabled(blacklistEnabled.isSelected());
            blacklist.setEditable(!blacklistEnabled.isSelected());
        });
        suffixFilterEnabled.addActionListener(e -> {
            state.suffixFilterText(suffixFilters.getText());
            state.suffixFilterEnabled(suffixFilterEnabled.isSelected());
            suffixFilters.setEditable(!suffixFilterEnabled.isSelected());
        });
        payloadGroupMode.addActionListener(e -> state.payloadGroupMode((PayloadGroupMode) payloadGroupMode.getSelectedItem()));

        JButton applyPayloads = new JButton("加载 payload");
        applyPayloads.addActionListener(e -> state.customPayloadText(payloadText.getText()));
        JButton applyErrors = new JButton("加载错误特征");
        applyErrors.addActionListener(e -> state.errorPatternText(errorPatterns.getText()));
        JButton clear = new JButton("清空列表");
        clear.addActionListener(e -> logStore.clear());
        JButton clearUiLog = new JButton("清空日志");
        clearUiLog.addActionListener(e -> {
            state.clearUiLog();
            refreshUiLog();
        });

        JPanel generalPanel = new JPanel(new BorderLayout());
        generalPanel.setBorder(new EmptyBorder(8, 8, 8, 8));

        JPanel generalHeader = new JPanel(new BorderLayout(0, 6));
        JLabel title = new JLabel("SqlScout");
        generalHeader.add(title, BorderLayout.NORTH);

        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        actionRow.add(enabled);
        actionRow.add(clear);
        generalHeader.add(actionRow, BorderLayout.SOUTH);

        JPanel detectionPanel = createSectionPanel("监听与检测");
        JPanel detectionGrid = new JPanel(new GridLayout(4, 1, 4, 4));
        detectionGrid.add(monitorRepeater);
        detectionGrid.add(monitorProxy);
        detectionGrid.add(numeric);
        detectionGrid.add(cookies);
        detectionPanel.add(detectionGrid, BorderLayout.CENTER);

        JPanel payloadPanel = createSectionPanel("自定义策略");
        JPanel payloadGrid = new JPanel(new GridLayout(1, 2, 8, 2));
        payloadGrid.setBorder(new EmptyBorder(0, 0, 0, 0));

        JPanel leftStrategyColumn = new JPanel(new GridLayout(2, 1, 4, 2));
        leftStrategyColumn.add(customPayloads);
        leftStrategyColumn.add(encodeSpaces);

        JPanel rightStrategyColumn = new JPanel(new GridLayout(2, 1, 4, 2));
        rightStrategyColumn.add(blankValues);
        rightStrategyColumn.add(new JLabel(""));

        payloadGrid.add(leftStrategyColumn);
        payloadGrid.add(rightStrategyColumn);
        payloadPanel.add(payloadGrid, BorderLayout.CENTER);

        JPanel generalBody = new JPanel();
        generalBody.setLayout(new BoxLayout(generalBody, BoxLayout.Y_AXIS));
        generalBody.add(detectionPanel);
        generalBody.add(Box.createVerticalStrut(6));
        generalBody.add(payloadPanel);

        JPanel generalContent = new JPanel();
        generalContent.setLayout(new BoxLayout(generalContent, BoxLayout.Y_AXIS));
        generalContent.add(generalHeader);
        generalContent.add(Box.createVerticalStrut(8));
        generalContent.add(generalBody);

        generalPanel.add(generalContent, BorderLayout.NORTH);

        JPanel whitelistPanel = createListConfigPanel("白名单域名，多个用逗号分隔", whitelist, whitelistEnabled);
        JPanel blacklistPanel = createListConfigPanel("黑名单域名，多个用逗号分隔", blacklist, blacklistEnabled);
        JPanel suffixFilterPanel = createListConfigPanel("后缀过滤，多个用逗号分隔", suffixFilters, suffixFilterEnabled);
        JPanel payloadModePanel = createSelectionPanel("Payload 分组", payloadGroupMode);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("常规", new JScrollPane(generalPanel));
        tabs.addTab("白名单", whitelistPanel);
        tabs.addTab("黑名单", blacklistPanel);
        tabs.addTab("后缀过滤", suffixFilterPanel);
        tabs.addTab("隐藏参数", withButton(hiddenParams, new JButton("实时保存")));
        tabs.addTab("Payload 分组", payloadModePanel);
        tabs.addTab("自定义 SQL", withButton(payloadText, applyPayloads));
        tabs.addTab("报错特征", withButton(errorPatterns, applyErrors));
        tabs.addTab("日志", withButton(uiLogArea, clearUiLog));

        JPanel container = new JPanel(new BorderLayout());
        container.add(tabs, BorderLayout.CENTER);
        return container;
    }

    private static Component withButton(JTextArea textArea, JButton button) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));
        panel.add(new JScrollPane(textArea), BorderLayout.CENTER);
        panel.add(button, BorderLayout.SOUTH);
        return panel;
    }

    private static JPanel createListConfigPanel(String title, JTextField textField, JCheckBox enabledCheckBox) {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));

        JLabel label = new JLabel(title);
        label.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));

        JPanel top = new JPanel(new BorderLayout(0, 6));
        top.add(label, BorderLayout.NORTH);
        top.add(textField, BorderLayout.CENTER);

        JPanel bottom = new JPanel(new BorderLayout());
        bottom.add(enabledCheckBox, BorderLayout.WEST);

        panel.add(top, BorderLayout.NORTH);
        panel.add(bottom, BorderLayout.SOUTH);
        return panel;
    }

    private static JPanel createSectionPanel(String title) {
        JPanel panel = new JPanel(new BorderLayout(0, 6));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(title),
                new EmptyBorder(4, 6, 4, 6)));
        return panel;
    }

    private static JPanel createSelectionPanel(String title, JComboBox<?> comboBox) {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));
        JLabel label = new JLabel(title);
        JPanel content = new JPanel(new BorderLayout(0, 6));
        content.add(label, BorderLayout.NORTH);
        content.add(comboBox, BorderLayout.CENTER);
        panel.add(content, BorderLayout.NORTH);
        return panel;
    }

    private void show(HttpRequestResponse requestResponse) {
        if (requestResponse == null) {
            return;
        }
        requestEditor.setRequest(requestResponse.request());
        if (requestResponse.response() != null) {
            responseEditor.setResponse(requestResponse.response());
        }
    }

    private void refreshTables() {
        mainTableModel.reload();
        attemptTableModel.reload();
        refreshUiLog();
    }

    private void refreshUiLog() {
        uiLogArea.setText(String.join("\n", state.uiLogSnapshot()));
    }

    private final class MainTableModel extends AbstractTableModel {
        private final String[] columns = {"#", "来源", "URL", "返回包长度", "状态"};
        private List<ScanLogEntry> entries = Collections.emptyList();

        void reload() {
            entries = logStore.scans();
            fireTableDataChanged();
        }

        ScanLogEntry entryAt(int row) {
            return entries.get(row);
        }

        @Override
        public int getRowCount() {
            return entries.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            ScanLogEntry entry = entries.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return entry.id();
                case 1:
                    return entry.toolType().toolName();
                case 2:
                    return entry.url();
                case 3:
                    return entry.responseLength();
                case 4:
                    return entry.state();
                default:
                    return "";
            }
        }
    }

    private final class AttemptTableModel extends AbstractTableModel {
        private final String[] columns = {"参数", "payload", "返回包长度", "变化", "相似度", "判定", "用时", "响应码", "变异器"};
        private List<ScanLogEntry> entries = Collections.emptyList();

        void reload() {
            entries = selectedFingerprint.trim().isEmpty() ? Collections.emptyList() : logStore.attemptsFor(selectedFingerprint);
            fireTableDataChanged();
        }

        ScanLogEntry entryAt(int row) {
            return entries.get(row);
        }

        @Override
        public int getRowCount() {
            return entries.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            ScanLogEntry entry = entries.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return entry.parameter();
                case 1:
                    return entry.payloadValue();
                case 2:
                    return entry.responseLength();
                case 3:
                    return entry.change();
                case 4:
                    return formatSimilarity(entry.similarity());
                case 5:
                    return entry.verdict().displayName();
                case 6:
                    return entry.durationMillis();
                case 7:
                    return entry.statusCode();
                case 8:
                    return entry.mutatorName();
                default:
                    return "";
            }
        }
    }

    private static String formatSimilarity(double similarity) {
        return String.format("%.1f%%", similarity * 100.0);
    }
}
