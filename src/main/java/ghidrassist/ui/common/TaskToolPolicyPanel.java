package ghidrassist.ui.common;

import ghidrassist.tools.api.Tool;
import ghidrassist.tools.registry.ToolExecutionPolicy;
import ghidrassist.tools.registry.ToolRegistry;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

/** In-memory task/conversation settings. Editing is separate from the applied policy. */
public final class TaskToolPolicyPanel extends JPanel {
    public enum Mode {
        ALL("All available tools"), READ_ONLY("Read-only tools"), SELECTED("Selected tools");
        private final String label;
        Mode(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }
    public enum Lifetime {
        NEXT_TASK("Next task"), CONVERSATION("Current conversation");
        private final String label;
        Lifetime(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }
    private record Settings(Mode mode, Lifetime lifetime, Set<String> selected,
                            Map<String,Integer> limits, Integer total) {
        static Settings defaults() { return new Settings(Mode.ALL, Lifetime.NEXT_TASK, Set.of(), Map.of(), null); }
    }
    private Settings applied = Settings.defaults();
    private final JComboBox<Mode> mode = new JComboBox<>(Mode.values());
    private final JComboBox<Lifetime> lifetime = new JComboBox<>(Lifetime.values());
    private final JTextField total = new JTextField(6);
    private final JTextField search = new JTextField(24);
    private final JComboBox<String> provider = new JComboBox<>();
    private final JLabel count = new JLabel();
    private final JTextArea notice = new JTextArea(2, 40);
    private final JTextArea description = new JTextArea(3, 40);
    private final JButton configure = new JButton();
    private final JButton history = new JButton("Tool history");
    private final JButton apply = new JButton("Apply");
    private final JButton refreshButton;
    private final List<JComponent> editControls = new ArrayList<>();
    private boolean running, updating;
    private JDialog dialog, historyDialog, helpDialog;
    private final DefaultTableModel tools = new DefaultTableModel(new Object[]{"Tool (full name)", "Allowed", "Max calls", "Provider", "Description"}, 0) {
        @Override public Class<?> getColumnClass(int col) { return col == 1 ? Boolean.class : String.class; }
        @Override public boolean isCellEditable(int row, int col) {
            return !running && (col == 2 || col == 1 && mode.getSelectedItem() == Mode.SELECTED);
        }
        @Override public Object getValueAt(int row, int col) {
            if (col == 1 && mode.getSelectedItem() != Mode.SELECTED)
                return mode.getSelectedItem() == Mode.ALL || ToolRegistry.isReadOnlyLookup((String)super.getValueAt(row, 0));
            return super.getValueAt(row, col);
        }
    };
    private final JTable table = new JTable(tools) {
        @Override public String getToolTipText(MouseEvent event) {
            int row = rowAtPoint(event.getPoint()), col = columnAtPoint(event.getPoint());
            if (row < 0 || col < 0) return null;
            if (col == 0) {
                Object details = getValueAt(row, 4);
                return details == null || details.toString().isBlank()
                    ? "No description supplied by this tool." : "<html><body style='width:420px'>"
                        + escapeHtml(details.toString()) + "</body></html>";
            }
            if (col == 1) return mode.getSelectedItem() == Mode.SELECTED
                ? "Click the checkbox to allow or disallow this tool."
                : "Switch Mode to Selected tools to change the allowlist.";
            if (col == 2) return "Enter a nonnegative number; clear the cell for Unlimited.";
            Object value = getValueAt(row, col);
            return value == null ? null : value.toString();
        }
    };
    private static String escapeHtml(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    .replace("\"", "&quot;").replace("\n", "<br>");
    }
    private final TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(tools);
    private final DefaultTableModel events = new DefaultTableModel(new Object[]{"Tool", "State", "Response / reason"}, 0) {
        @Override public boolean isCellEditable(int row, int col) { return false; }
    };
    private final Map<String,Integer> eventRows = new LinkedHashMap<>();

    public TaskToolPolicyPanel(Runnable refresh) {
        super(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        mode.setName("task-policy-mode"); lifetime.setName("task-policy-lifetime");
        table.setName("task-policy-tools"); total.setName("task-policy-total"); search.setName("task-policy-search");
        configure.setName("task-policy-open"); history.setName("task-history-open"); apply.setName("task-policy-apply");
        mode.setToolTipText("Choose all tools, the registry's read-only tools, or an explicit allowlist.");
        lifetime.setToolTipText("Next task resets after execution; Current conversation resets when you leave or start a conversation. Nothing is saved to preferences.");
        total.setToolTipText("Maximum actual tool executions in each task. Blank = Unlimited; 0 blocks all executions.");
        search.setToolTipText("Filter by full tool name or the description supplied by its provider.");
        provider.setToolTipText("Group/filter the inventory by its actual tool provider. Selection and limits survive filtering.");
        provider.setPrototypeDisplayValue("mcp:tool-provider-name");
        table.setToolTipText("Allowed applies in Selected tools mode. Max calls: blank = Unlimited; 0 blocks this tool. Aliases share budgets.");
        table.getTableHeader().setToolTipText("Full names and descriptions are available by hovering or scrolling horizontally. Blank Max calls means Unlimited.");
        configure.setToolTipText("Configure the controller-enforced Agentic tool restrictions and their lifetime.");
        history.setToolTipText("Show the latest task's actual requests, executions, results and rejections.");
        apply.setToolTipText("Validate and apply these settings. They remain in memory only.");
        description.setEditable(false); description.setLineWrap(true); description.setWrapStyleWord(true);
        description.setToolTipText("Description supplied by the selected tool's provider; no description is invented.");
        notice.setEditable(false); notice.setLineWrap(true); notice.setWrapStyleWord(true); notice.setOpaque(false);
        JPanel controls = new JPanel(new WrapLayout());
        controls.add(fieldGroup("Mode:", mode));
        controls.add(fieldGroup("Applies to:", lifetime));
        controls.add(fieldGroup("Total calls:", total));
        JPanel filters = new JPanel(new WrapLayout());
        filters.add(fieldGroup("Search:", search)); filters.add(fieldGroup("Provider:", provider));
        refreshButton = button("Refresh tools", "Reload native tools and tools from MCP when Use MCP Tools is enabled.", refresh);
        filters.add(refreshButton);
        JButton select = button("Select all shown", "Allow every tool matching the current search/provider filter in Selected tools mode.", () -> selectShown(true));
        JButton deselect = button("Deselect all shown", "Disallow every tool matching the current search/provider filter in Selected tools mode.", () -> selectShown(false));
        filters.add(select); filters.add(deselect);
        JButton clearAll = button("Deselect all tools", "Switch to Selected tools and disallow every tool, including hidden rows.", () -> {
            mode.setSelectedItem(Mode.SELECTED);
            for (int r = 0; r < tools.getRowCount(); r++) tools.setValueAt(false, r, 1);
            updateCount();
        });
        filters.add(clearAll);
        JPanel north = new JPanel(new WrapLayout());
        for (Component c : controls.getComponents()) north.add(c);
        for (Component c : filters.getComponents()) north.add(c);
        north.add(count); add(north, BorderLayout.NORTH);
        table.setRowSorter(sorter); table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        // Make numeric limits easily resettable: a blank editing value means Unlimited.
        table.getColumnModel().getColumn(2).setCellEditor(new DefaultCellEditor(new JTextField()) {
            @Override public Component getTableCellEditorComponent(JTable t, Object value,
                    boolean selected, int row, int column) {
                return super.getTableCellEditorComponent(t,
                    value == null ? "" : value, selected, row, column);
            }
        });
        table.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
            .put(KeyStroke.getKeyStroke(KeyEvent.VK_SPACE, 0), "toggleAllowed");
        table.getActionMap().put("toggleAllowed", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) {
                int row = table.getSelectedRow();
                if (row < 0 || running || mode.getSelectedItem() != Mode.SELECTED || table.isEditing()) return;
                int modelRow = table.convertRowIndexToModel(row);
                tools.setValueAt(!Boolean.TRUE.equals(tools.getValueAt(modelRow, 1)), modelRow, 1);
            }
        });
        table.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() != 2 || running || mode.getSelectedItem() != Mode.SELECTED) return;
                int row = table.rowAtPoint(e.getPoint()), col = table.columnAtPoint(e.getPoint());
                if (row < 0 || col == 1 || col == 2 || table.isEditing()) return;
                int modelRow = table.convertRowIndexToModel(row);
                tools.setValueAt(!Boolean.TRUE.equals(tools.getValueAt(modelRow, 1)), modelRow, 1);
            }
        });
        int[] widths = {310, 75, 100, 160, 420};
        for (int i = 0; i < widths.length; i++) table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        table.getColumnModel().getColumn(2).setCellRenderer(new DefaultTableCellRenderer() {
            @Override protected void setValue(Object value) { super.setValue(value == null || value.toString().isBlank() ? "Unlimited" : value); }
        });
        sorter.setSortKeys(List.of(new RowSorter.SortKey(3, SortOrder.ASCENDING), new RowSorter.SortKey(0, SortOrder.ASCENDING)));
        JScrollPane rows = new JScrollPane(table);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, rows, new JScrollPane(description));
        split.setResizeWeight(.82); rows.setMinimumSize(new Dimension(100, 100)); description.setMinimumSize(new Dimension(100, 35));
        add(split, BorderLayout.CENTER);
        JButton defaults = button("Restore defaults", "Set all tools, Unlimited limits and Next task. Click Apply to confirm.", () -> loadDraft(Settings.defaults()));
        JButton help = button("Help (?)", "Explain Agentic Mode, tools, restrictions, limits and defaults.", this::showHelp);
        JButton cancel = button("Cancel", "Discard uncommitted edits and close this window.", () -> { if (dialog != null) dialog.setVisible(false); });
        apply.addActionListener(e -> applyDraft());
        JPanel actions = new JPanel(new WrapLayout()); actions.add(defaults); actions.add(help); actions.add(cancel); actions.add(apply);
        JPanel south = new JPanel(new BorderLayout()); south.add(notice, BorderLayout.NORTH); south.add(actions, BorderLayout.SOUTH); add(south, BorderLayout.SOUTH);
        editControls.addAll(List.of(mode, lifetime, total, search, provider, refreshButton, select, deselect, clearAll, defaults, apply));
        provider.addItem("All providers");
        mode.addActionListener(e -> {
            select.setEnabled(!running && mode.getSelectedItem() == Mode.SELECTED);
            deselect.setEnabled(!running && mode.getSelectedItem() == Mode.SELECTED);
            tools.fireTableDataChanged(); updateCount();
            notice.setText(mode.getSelectedItem() == Mode.SELECTED
                ? "Selected tools: use checkboxes, Space or double-click a tool. Blank Max calls = Unlimited."
                : "To select individual tools, change Mode to Selected tools. Deselect all tools switches automatically.");
        });
        addComponentListener(new ComponentAdapter() {
            @Override public void componentResized(ComponentEvent e) { revalidate(); }
        });
        provider.addActionListener(e -> filter());
        search.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { filter(); }
            public void removeUpdate(DocumentEvent e) { filter(); }
            public void changedUpdate(DocumentEvent e) { filter(); }
        });
        tools.addTableModelListener(e -> updateCount());
        table.getSelectionModel().addListSelectionListener(e -> {
            int row = table.getSelectedRow();
            String text = row < 0 ? "" : String.valueOf(table.getValueAt(row, 4));
            description.setText(row < 0 ? "" : "Tool: " + table.getValueAt(row,0) + "\nProvider: " + table.getValueAt(row,3) + "\n\n" +
                (text.isBlank() ? "No description supplied by this tool." : text)); description.setCaretPosition(0);
        });
        loadDraft(applied); updateSummary();
    }
    private static JLabel label(String text, JComponent target) { JLabel label = new JLabel(text); label.setLabelFor(target); return label; }
    private static JPanel fieldGroup(String text, JComponent target) {
        JPanel group = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 0));
        group.add(label(text,target)); group.add(target); return group;
    }
    private static JButton button(String text, String tooltip, Runnable action) {
        JButton b = new JButton(text); b.setToolTipText(tooltip); b.addActionListener(e -> action.run()); return b;
    }
    private void edt() { if (!SwingUtilities.isEventDispatchThread()) throw new IllegalStateException("Task policy UI requires EDT"); }
    public JButton getConfigureButton() { return configure; }
    public JButton getHistoryButton() { return history; }

    public void showConfiguration(Component owner, Runnable refresh) {
        edt(); if (running) return;
        loadDraft(applied);
        if (dialog == null) {
            dialog = window(owner, "Agentic task tools", this, new Dimension(1000, 650));
            dialog.setMinimumSize(new Dimension(580,460));
            dialog.getRootPane().setDefaultButton(apply);
        }
        dialog.setVisible(true); refresh.run();
    }
    private JDialog window(Component owner, String title, Component content, Dimension size) {
        Window parent = SwingUtilities.getWindowAncestor(owner);
        JDialog result = new JDialog(parent, title, Dialog.ModalityType.MODELESS);
        result.setDefaultCloseOperation(WindowConstants.HIDE_ON_CLOSE); result.setResizable(true);
        result.add(content); result.setMinimumSize(new Dimension(540, 380)); result.setSize(size);
        result.setLocationRelativeTo(owner);
        result.getRootPane().registerKeyboardAction(e -> result.setVisible(false), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);
        return result;
    }
    public void setInventoryError(String message) { edt(); notice.setText(message); notice.setToolTipText(message); }
    public void setTools(List<Tool> available) {
        edt(); if (running) return;
        Map<String,Object[]> old = new HashMap<>();
        for (int r = 0; r < tools.getRowCount(); r++) old.put((String)tools.getValueAt(r,0), new Object[]{tools.getDataVector().get(r).get(1), tools.getValueAt(r,2)});
        Map<String,Tool> unique = new TreeMap<>(); available.forEach(t -> unique.putIfAbsent(t.getName(),t));
        updating = true; tools.setRowCount(0);
        for (Tool tool : unique.values()) {
            Object[] previous = old.get(tool.getName());
            boolean allowed = previous == null ? mode.getSelectedItem() != Mode.SELECTED || applied.selected.contains(tool.getName()) : Boolean.TRUE.equals(previous[0]);
            String limit = previous == null ? limitText(applied.limits.get(tool.getName())) : String.valueOf(previous[1]);
            tools.addRow(new Object[]{tool.getName(), allowed, limit, tool.getSource() == null ? "Unspecified provider" : tool.getSource(), tool.getDescription() == null ? "" : tool.getDescription()});
        }
        int nameWidth = 310;
        for (String name : unique.keySet()) nameWidth = Math.max(nameWidth,table.getFontMetrics(table.getFont()).stringWidth(name)+24);
        table.getColumnModel().getColumn(0).setPreferredWidth(nameWidth);
        Object selected = provider.getSelectedItem(); provider.removeAllItems(); provider.addItem("All providers");
        unique.values().stream().map(t -> t.getSource() == null ? "Unspecified provider" : t.getSource()).distinct().sorted().forEach(provider::addItem);
        provider.setSelectedItem(selected); if (provider.getSelectedIndex() < 0) provider.setSelectedIndex(0);
        updating = false; notice.setText("Descriptions come from tool providers. Settings are applied only after Apply.");
        filter(); updateSummary();
    }
    private static String limitText(Integer value) { return value == null ? "" : value.toString(); }
    private void loadDraft(Settings value) {
        updating = true; mode.setSelectedItem(value.mode); lifetime.setSelectedItem(value.lifetime); total.setText(limitText(value.total));
        for (int r=0;r<tools.getRowCount();r++) {
            String name = (String)tools.getValueAt(r,0);
            tools.setValueAt(value.mode != Mode.SELECTED || value.selected.contains(name),r,1);
            tools.setValueAt(limitText(value.limits.get(name)),r,2);
        }
        search.setText(""); provider.setSelectedIndex(0); notice.setText("Nothing is saved to preferences. Blank limits mean Unlimited.");
        updating = false; filter();
    }
    private void filter() {
        if (updating) return;
        String query = search.getText().strip().toLowerCase(Locale.ROOT); Object source = provider.getSelectedItem();
        sorter.setRowFilter(new RowFilter<DefaultTableModel,Integer>() {
            @Override public boolean include(Entry<? extends DefaultTableModel,? extends Integer> entry) {
                return (source == null || source.equals("All providers") || source.equals(entry.getStringValue(3))) &&
                    (entry.getStringValue(0).toLowerCase(Locale.ROOT).contains(query) || entry.getStringValue(4).toLowerCase(Locale.ROOT).contains(query));
            }
        });
        updateCount();
    }
    private void selectShown(boolean selected) {
        if (running || mode.getSelectedItem() != Mode.SELECTED) return;
        for (int r=0;r<table.getRowCount();r++) tools.setValueAt(selected,table.convertRowIndexToModel(r),1);
        updateCount();
    }
    private void updateCount() {
        int allowed = 0; for (int r=0;r<tools.getRowCount();r++) if (Boolean.TRUE.equals(tools.getValueAt(r,1))) allowed++;
        count.setText("Allowed: " + allowed + " / " + tools.getRowCount() + " available tools; shown: " + table.getRowCount());
    }
    private void applyDraft() {
        edt(); if (running) return;
        try {
            if (table.isEditing() && !table.getCellEditor().stopCellEditing()) throw new IllegalArgumentException("Finish editing the tool limit.");
            Set<String> selected = new LinkedHashSet<>(); Map<String,Integer> limits = new LinkedHashMap<>();
            for (int r=0;r<tools.getRowCount();r++) {
                String name = (String)tools.getValueAt(r,0);
                if (Boolean.TRUE.equals(tools.getDataVector().get(r).get(1))) selected.add(name);
                String raw = String.valueOf(tools.getValueAt(r,2)).strip(); if (!raw.isEmpty()) limits.put(name,parse(raw));
            }
            applied = new Settings((Mode)mode.getSelectedItem(), (Lifetime)lifetime.getSelectedItem(), Set.copyOf(selected), Map.copyOf(limits), total.getText().isBlank() ? null : parse(total.getText().strip()));
            updateSummary(); notice.setText("Settings applied."); if (dialog != null) dialog.setVisible(false);
        } catch (IllegalArgumentException error) { notice.setText(error.getMessage()); notice.setToolTipText(error.getMessage()); }
    }
    private int parse(String value) {
        try { int limit = Integer.parseInt(value); if (limit < 0) throw new NumberFormatException(); return limit; }
        catch (NumberFormatException error) { throw new IllegalArgumentException("Limits must be nonnegative integers. Leave blank for Unlimited."); }
    }
    /** Snapshot only committed settings. An unchanged default keeps the existing legacy overload. */
    public ToolExecutionPolicy snapshot() {
        edt();
        if (applied.mode == Mode.ALL && applied.limits.isEmpty() && applied.total == null) return null;
        return new ToolExecutionPolicy(applied.mode == Mode.SELECTED ? applied.selected : null, applied.limits, applied.total, applied.mode == Mode.READ_ONLY);
    }
    private void updateSummary() {
        long selected = applied.selected.stream().filter(name -> {
            for(int r=0;r<tools.getRowCount();r++) if(name.equals(tools.getValueAt(r,0))) return true;
            return false;
        }).count();
        String state = applied.mode == Mode.SELECTED ? "Selected: " + selected : applied.mode == Mode.READ_ONLY ? "Read-only" : "All tools";
        if (applied.mode == Mode.ALL && (applied.total != null || !applied.limits.isEmpty())) state += " (limited)";
        configure.setText("Tools: " + state + (applied.lifetime == Lifetime.CONVERSATION ? " / chat" : " / next"));
        configure.setToolTipText("Agentic restrictions: " + state + "; " + applied.lifetime + ". Total calls: " + (applied.total == null ? "Unlimited" : applied.total) + ". Per-tool limits: " + applied.limits.size() + ". Click to configure.");
        configure.setEnabled(!running);
    }
    public void beginExecution() {
        edt(); running = true; configure.setEnabled(false); editControls.forEach(c -> c.setEnabled(false));
        if (dialog != null) dialog.setVisible(false); eventRows.clear(); events.setRowCount(0);
    }
    public void finishExecution() {
        edt(); running = false; editControls.forEach(c -> c.setEnabled(true));
        if (applied.lifetime == Lifetime.NEXT_TASK) applied = Settings.defaults();
        loadDraft(applied); updateSummary();
    }
    /** A conversation boundary clears both lifetimes and the optional latest-task history. */
    public void resetForNewTask() {
        edt(); applied = Settings.defaults(); running = false; editControls.forEach(c -> c.setEnabled(true));
        loadDraft(applied); updateSummary(); eventRows.clear(); events.setRowCount(0);
        if (dialog != null) dialog.setVisible(false); if (historyDialog != null) historyDialog.setVisible(false);
    }
    public void record(String id, String tool, String state, String text) {
        Runnable update = () -> {
            Integer row = eventRows.get(id);
            if (row == null) { row = events.getRowCount(); eventRows.put(id,row); events.addRow(new Object[]{tool,state,text}); }
            String resolved = state;
            if (state.equals("FAILED")) resolved = String.valueOf(events.getValueAt(row,1)).equals("RUNNING") ? "FAILED" : "REJECTED";
            events.setValueAt(resolved,row,1); events.setValueAt(text,row,2);
        };
        if (SwingUtilities.isEventDispatchThread()) update.run(); else SwingUtilities.invokeLater(update);
    }
    public void showHistory(Component owner) {
        edt();
        if (historyDialog == null) {
            JTable rows = new JTable(events); rows.setName("task-tool-outcomes"); rows.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
            rows.getColumnModel().getColumn(0).setPreferredWidth(330); rows.getColumnModel().getColumn(1).setPreferredWidth(110); rows.getColumnModel().getColumn(2).setPreferredWidth(600);
            rows.setToolTipText("Actual observer events from the latest task. Select a row to read the full response or rejection reason.");
            JTextArea detail = new JTextArea(); detail.setEditable(false); detail.setLineWrap(true); detail.setWrapStyleWord(true);
            rows.getSelectionModel().addListSelectionListener(e -> { int row=rows.getSelectedRow(); detail.setText(row < 0 ? "" : String.valueOf(rows.getValueAt(row,2))); detail.setCaretPosition(0); });
            JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(rows), new JScrollPane(detail)); split.setResizeWeight(.6);
            historyDialog = window(owner,"Tool execution history - latest task",split,new Dimension(900,550));
        }
        historyDialog.setVisible(true);
    }
    private void showHelp() {
        if (helpDialog == null) {
            JEditorPane text = new JEditorPane("text/html", "<html><body style='font-family:sans-serif;padding:12px'>" +
                "<h2>Agentic task tools</h2><p><b>Agentic Mode</b> lets the model plan an investigation, request tools, read their results and produce an answer. The controller decides whether each request can execute.</p>" +
                "<p><b>Tools</b> are native GhidrAssist functions or functions supplied by MCP servers. Names and descriptions here come from those providers.</p>" +
                "<p><b>Allowed</b> selects an explicit allowlist in Selected tools mode. All available tools has no allowlist. Read-only tools uses the registry's existing read classification (names containing get_, list_ or search_); it is not an independent audit of remote server behavior. Existing approvals and protections still apply.</p>" +
                "<p><b>Max calls</b> limits executions of one tool in each task. Aliases share budgets. Changing arguments does not reset a budget. <b>Total calls</b> limits all actual executions in each task. Blank means <b>Unlimited</b>; zero blocks executions. Rejected requests do not consume execution budgets.</p>" +
                "<p><b>One tool only:</b> choose Selected tools, clear Search, select All providers, Deselect all shown, then allow the exact full tool name. Set its Max calls and Total calls to 1, then Apply.</p>" +
                "<p><b>Lifetime:</b> Next task resets after completion, failure or cancellation of an executing task. Cancelling a plan does not consume it. Current conversation applies to each task until you start or switch conversations. Closing the editor or clicking Cancel discards unsaved edits. No settings are saved to preferences or restored from chat history.</p>" +
                "<p><b>Restore defaults</b> selects all tools, Unlimited budgets and Next task. Click Apply to confirm. <b>Tool history</b> is a separate view of requests, starts, successes, rejections and failures from the latest task.</p></body></html>");
            text.setEditable(false); helpDialog = window(this,"Help - Agentic task tools",new JScrollPane(text),new Dimension(740,600));
        }
        helpDialog.setVisible(true);
    }
    public void dispose() {
        Runnable close = () -> { if(dialog!=null)dialog.dispose(); if(historyDialog!=null)historyDialog.dispose(); if(helpDialog!=null)helpDialog.dispose(); };
        if (SwingUtilities.isEventDispatchThread()) close.run(); else SwingUtilities.invokeLater(close);
    }
}
