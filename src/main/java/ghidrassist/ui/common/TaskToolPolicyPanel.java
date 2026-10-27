package ghidrassist.ui.common;

import ghidrassist.tools.api.Tool;
import ghidrassist.tools.registry.ToolExecutionPolicy;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;

/** Task-local, explicit controller settings; never derived from prompt text or persisted. */
public final class TaskToolPolicyPanel extends JPanel {
    private final JCheckBox enabled = new JCheckBox("Restrict tools for this task");
    private final JCheckBox readOnly = new JCheckBox("Read-only tools");
    private final JTextField total = new JTextField(5);
    private final DefaultTableModel tools = new DefaultTableModel(new Object[]{"Tool", "Allowed", "Max calls (blank = unlimited)"}, 0) {
        public Class<?> getColumnClass(int column) { return column == 1 ? Boolean.class : String.class; }
        public boolean isCellEditable(int row, int column) { return enabled.isSelected() && !running && column > 0; }
    };
    private final JTable table = new JTable(tools);
    private final DefaultTableModel events = new DefaultTableModel(new Object[]{"Tool", "State", "Response / reason"}, 0) {
        public boolean isCellEditable(int row, int column) { return false; }
    };
    private final Map<String,Integer> eventRows = new LinkedHashMap<>();
    private final JLabel notice = new JLabel("Task settings are separate from model instructions. Aliases share budgets; settings reset after execution.");
    private final JPanel editor = new JPanel(new BorderLayout());
    private boolean running;

    public TaskToolPolicyPanel(Runnable refresh) {
        super(new BorderLayout(4,4));
        setBorder(BorderFactory.createTitledBorder("Agentic task tools"));
        enabled.setName("task-policy-enabled"); table.setName("task-policy-tools"); total.setName("task-policy-total");
        JButton reload = new JButton("Refresh tools"); reload.setName("task-policy-refresh");
        reload.addActionListener(e -> refresh.run());
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controls.add(enabled); controls.add(reload); controls.add(readOnly); controls.add(new JLabel("Total calls:")); controls.add(total);
        add(controls, BorderLayout.NORTH);
        JScrollPane rows = new JScrollPane(table); rows.setPreferredSize(new Dimension(600,100));
        editor.add(rows, BorderLayout.CENTER); editor.add(notice, BorderLayout.SOUTH); add(editor, BorderLayout.CENTER);
        JTable outcomes = new JTable(events); outcomes.setName("task-tool-outcomes");
        JScrollPane results = new JScrollPane(outcomes); results.setPreferredSize(new Dimension(600,80)); add(results, BorderLayout.SOUTH);
        enabled.addActionListener(e -> editor.setVisible(enabled.isSelected())); editor.setVisible(false);
    }
    private void edt() { if (!SwingUtilities.isEventDispatchThread()) throw new IllegalStateException("Task policy UI requires EDT"); }
    public void setTools(List<Tool> available) {
        edt(); if (running) return;
        Map<String,Object[]> old = new HashMap<>();
        for (int r=0;r<tools.getRowCount();r++) old.put((String)tools.getValueAt(r,0), new Object[]{tools.getValueAt(r,1),tools.getValueAt(r,2)});
        tools.setRowCount(0);
        available.stream().map(Tool::getName).distinct().sorted().forEach(name -> {
            Object[] prior=old.get(name);
            tools.addRow(new Object[]{name, prior == null ? !enabled.isSelected() : prior[0], prior == null ? "" : prior[1]});
        });
    }
    public ToolExecutionPolicy snapshot() {
        edt();
        if (!enabled.isSelected()) return null; // Preserve the legacy overload exactly.
        if (table.isEditing() && !table.getCellEditor().stopCellEditing()) throw new IllegalArgumentException("Finish editing the tool limit");
        Set<String> allowed = new LinkedHashSet<>(); Map<String,Integer> budgets = new LinkedHashMap<>();
        for (int r=0;r<tools.getRowCount();r++) {
            String name=(String)tools.getValueAt(r,0);
            if (Boolean.TRUE.equals(tools.getValueAt(r,1))) allowed.add(name);
            String value=String.valueOf(tools.getValueAt(r,2)).trim();
            if (!value.isEmpty()) budgets.put(name, parse(value));
        }
        return new ToolExecutionPolicy(allowed,budgets,total.getText().isBlank()?null:parse(total.getText().trim()),readOnly.isSelected());
    }
    private int parse(String value) {
        try { int limit=Integer.parseInt(value); if(limit<0) throw new NumberFormatException(); return limit; }
        catch(NumberFormatException error) { throw new IllegalArgumentException("Tool call limits must be nonnegative integers"); }
    }
    public void beginExecution() { edt(); running=true; enabled.setEnabled(false); total.setEnabled(false); readOnly.setEnabled(false); eventRows.clear(); events.setRowCount(0); }
    public void finishExecution() {
        edt(); running=false; enabled.setEnabled(true); total.setEnabled(true); readOnly.setEnabled(true);
        enabled.setSelected(false); editor.setVisible(false); total.setText(""); readOnly.setSelected(false);
        for(int r=0;r<tools.getRowCount();r++){tools.setValueAt(true,r,1);tools.setValueAt("",r,2);}
    }
    public void resetForNewTask() { edt(); finishExecution(); eventRows.clear(); events.setRowCount(0); }
    public void record(String id,String tool,String state,String text) {
        Runnable update=()->{
            Integer row=eventRows.get(id);
            if(row==null){row=events.getRowCount();eventRows.put(id,row);events.addRow(new Object[]{tool,state,text});}
            if(state.equals("FAILED")) {
                String previous=String.valueOf(events.getValueAt(row,1));
                stateUpdate(row, previous.equals("RUNNING")?"FAILED":"REJECTED",text);
            } else stateUpdate(row,state,text);
        };
        if(SwingUtilities.isEventDispatchThread())update.run();else SwingUtilities.invokeLater(update);
    }
    private void stateUpdate(int row,String state,String text){events.setValueAt(state,row,1);events.setValueAt(text,row,2);}
}
