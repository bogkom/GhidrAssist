package ghidrassist.ui.tabs;

import ghidrassist.GhidrAssistPlugin;
import ghidrassist.hardware.HardwareInventoryService;
import ghidrassist.hardware.HardwareApplyPlan;
import ghidrassist.hardware.HardwareApplyService;
import ghidrassist.core.MarkdownHelper;
import ghidra.app.services.GoToService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingWorker;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JCheckBox;
import javax.swing.table.DefaultTableModel;
import java.awt.Dimension;
import java.util.List;
import java.util.ArrayList;
import javax.swing.filechooser.FileNameExtensionFilter;

/**
 * Local, deterministic hardware evidence UI. It makes no model/API requests,
 * never writes to Ghidra's Program database and never infers physical wiring.
 */
public final class HardwareAnalysisTab extends JPanel {
    private static final long serialVersionUID=1L;
    private static final Pattern LINK_ADDRESS=Pattern.compile(
        "(?i)(?<![0-9a-f])(?:FUN_)?(?:0x)?([0-9a-f]{6,8})(?![0-9a-f])");
    private final GhidrAssistPlugin plugin;
    private final JComboBox<String> selection=new JComboBox<>(new String[]{
        "CPU32 — survey MC68332 address hypotheses",
        "MC68332 — user-selected device hypothesis"
    });
    private final JButton run=new JButton("Analyze current program");
    private final JButton export=new JButton("Export evidence Markdown for RAG");
    private final JButton namePreview=new JButton("Export naming review CSV");
    private final JButton approve=new JButton("Review / Apply hardware definitions...");
    private final JTextArea report=new JTextArea();
    private final JLabel status=new JLabel("Open a Ghidra program, then analyze candidate MCU registers.");
    private volatile String latestMarkdown;
    private volatile String latestNameCsv;
    private volatile Program latestProgram;
    private volatile boolean latestConcrete;

    public HardwareAnalysisTab(GhidrAssistPlugin plugin){
        super(new BorderLayout(5,5));
        this.plugin=plugin;
        JPanel controls=new JPanel(new FlowLayout(FlowLayout.LEFT,5,3));
        controls.add(new JLabel("Profile:"));
        controls.add(selection);
        controls.add(run);
        controls.add(export);
        controls.add(namePreview);
        controls.add(approve);
        approve.setEnabled(false);
        export.setEnabled(false);
        namePreview.setEnabled(false);
        report.setEditable(false);
        refreshAppearance();
        report.setToolTipText("Double-click an address or FUN_... to navigate in Ghidra Listing");
        report.addMouseListener(new MouseAdapter(){
            @Override public void mouseClicked(MouseEvent e){
                if(e.getClickCount()==2) navigateFromReport(e);
            }
        });
        report.setText(
            "Hardware Analysis (READ ONLY)\n\n"+
            "This tab scans existing Ghidra code references to candidate\n"+
            "MC68332 registers in both MM address maps.\n"+
            "The CPU32 language alone does not identify a physical MCU.\n"+
            "Reported chip-select windows are hypothetical and do not\n"+
            "authorize programming or scanning actual hardware.\n\n"+
            "After analysis, relevant evidence can be injected into AI queries.\n"+
            "Use #hardware in a query to request evidence explicitly.\n"+
            "No API credits or network are needed for this analysis.");
        add(controls,BorderLayout.NORTH);
        add(new JScrollPane(report),BorderLayout.CENTER);
        status.setBorder(BorderFactory.createEmptyBorder(4,8,5,8));
        add(status,BorderLayout.SOUTH);
        run.addActionListener(e->startScan());
        export.addActionListener(e->exportMarkdown());
        namePreview.addActionListener(e->exportNamingPreview());
        approve.addActionListener(e->reviewHardwareChanges());
    }

    /** Uses the very same saved settings as Settings > Response Appearance. */
    public void refreshAppearance(){
        String family=MarkdownHelper.getResponseFontFamily();
        int size=MarkdownHelper.getResponseFontSize();
        report.setFont(new Font(family==null?Font.MONOSPACED:family,Font.PLAIN,size));
    }
    private void navigateFromReport(MouseEvent event){
        int clicked=report.viewToModel2D(event.getPoint());
        if(clicked<0)return;
        String text=report.getText();
        if(clicked>=text.length())return;
        int from=text.lastIndexOf('\n',clicked)+1;
        int end=text.indexOf('\n',clicked);
        if(end<0)end=text.length();
        Matcher match=LINK_ADDRESS.matcher(text.substring(from,end));
        while(match.find()){
            if(clicked-from<match.start()||clicked-from>match.end())continue;
            Program program=plugin.getCurrentProgram();
            if(program==null || program!=latestProgram){
                status.setText("Program changed; rerun Hardware Analysis before navigating.");
                return;
            }
            try{
                long offset=Long.parseUnsignedLong(match.group(1),16);
                Address address=program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(offset);
                GoToService service=plugin.getTool().getService(GoToService.class);
                if(service==null || !service.goTo(address,program))
                    status.setText("Could not navigate to "+address+
                        ". Define memory there if the address is not mapped.");
                else status.setText("Listing: "+address);
            }catch(Exception ex){
                status.setText("Address navigation error: "+ex.getMessage());
            }
            return;
        }
    }
    private void startScan(){
        final Program program=plugin.getCurrentProgram();
        if(program==null){
            JOptionPane.showMessageDialog(this,"Open a program in CodeBrowser first.",
                "Hardware analysis",JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        final boolean concrete=selection.getSelectedIndex()==1;
        run.setEnabled(false);export.setEnabled(false);namePreview.setEnabled(false);
        approve.setEnabled(false);
        latestMarkdown=null;latestNameCsv=null;latestProgram=null;
        ghidrassist.hardware.HardwareEvidenceCache.clear(program);
        status.setText("Scanning references and disassembled instructions. Read-only.");
        SwingWorker<HardwareInventoryService.Report,Void> worker=
                new SwingWorker<>() {
            @Override protected HardwareInventoryService.Report doInBackground()throws Exception{
                return new HardwareInventoryService().scan(program,concrete,
                    ghidra.util.task.TaskMonitor.DUMMY);
            }
            @Override protected void done(){
                run.setEnabled(true);
                try {
                    HardwareInventoryService.Report finished=get();
                    if(plugin.getCurrentProgram()!=program){
                        report.setText("Program changed while analyzing. Rerun on the active program.");
                        status.setText("Result discarded; program changed.");
                        return;
                    }
                    latestMarkdown=finished.markdown;
                    latestNameCsv=finished.namePreviewCsv;
                    latestProgram=program;
                    latestConcrete=concrete;
                    approve.setEnabled(true);
                    ghidrassist.hardware.HardwareEvidenceCache.publish(program, finished.markdown);
                    report.setText(finished.markdown);
                    report.setCaretPosition(0);
                    export.setEnabled(true);
                    namePreview.setEnabled(true);
                    status.setText("Read-only: "+finished.uniqueSites+
                        " candidate sites in "+finished.functions+" functions. No database edits.");
                }catch(Exception ex){
                    Throwable root=ex;
                    while(root.getCause()!=null && root.getCause()!=root)
                        root=root.getCause();
                    ghidra.util.Msg.error(HardwareAnalysisTab.this,
                        "Hardware Analysis failed; detailed stack trace follows",ex);
                    report.setText("Hardware analysis failed:\n"+
                        root.getClass().getSimpleName()+": "+root.getMessage()+
                        "\n\nFull stack trace is in Ghidra Application Log."+
                        "\nNo program changes.");
                    status.setText("Analysis failed; inspect Ghidra Application Log.");
                }
            }
        };
        worker.execute();
    }
    private void exportMarkdown(){
        if(latestMarkdown==null || latestProgram!=plugin.getCurrentProgram()){
            export.setEnabled(false);
            status.setText("Program changed; run analysis again before export.");
            return;
        }
        JFileChooser chooser=new JFileChooser();
        chooser.setDialogTitle("Save hardware evidence for manual GhidrAssist RAG import");
        chooser.setFileFilter(new FileNameExtensionFilter("Markdown evidence (*.md)","md"));
        chooser.setSelectedFile(new File("GhidrAssist_Hardware_Evidence.md"));
        if(chooser.showSaveDialog(this)!=JFileChooser.APPROVE_OPTION)return;
        File selected=chooser.getSelectedFile();
        String name=selected.getName();
        if(!name.toLowerCase(java.util.Locale.ROOT).endsWith(".md"))
            selected=new File(selected.getParentFile(),name+".md");
        if(selected.isFile() && JOptionPane.showConfirmDialog(this,
                "Replace existing file?\n"+selected.getAbsolutePath(),
                "Confirm export",JOptionPane.YES_NO_OPTION)!=JOptionPane.YES_OPTION)
            return;
        try{
            Files.writeString(selected.toPath(),latestMarkdown,StandardCharsets.UTF_8);
            status.setText("Markdown saved; import manually in GhidrAssist > RAG > Add Documents.");
        }catch(Exception ex){
            JOptionPane.showMessageDialog(this,"Cannot save evidence:\n"+ex.getMessage(),
                "Export error",JOptionPane.ERROR_MESSAGE);
        }
    }
    private void exportNamingPreview(){
        if(latestNameCsv==null || latestProgram!=plugin.getCurrentProgram()){
            namePreview.setEnabled(false);
            status.setText("Program changed; rerun analysis before exporting naming review.");
            return;
        }
        JFileChooser chooser=new JFileChooser();
        chooser.setDialogTitle("Export review-only hardware label proposals (never applied)");
        chooser.setFileFilter(new FileNameExtensionFilter("CSV naming review (*.csv)","csv"));
        chooser.setSelectedFile(new File("GhidrAssist_Hardware_Name_Review.csv"));
        if(chooser.showSaveDialog(this)!=JFileChooser.APPROVE_OPTION)return;
        File dest=chooser.getSelectedFile();
        if(!dest.getName().toLowerCase(java.util.Locale.ROOT).endsWith(".csv"))
            dest=new File(dest.getParentFile(),dest.getName()+".csv");
        if(dest.isFile() && JOptionPane.showConfirmDialog(this,
                "Replace existing CSV file?\n"+dest.getAbsolutePath(),
                "Confirm review-only export",JOptionPane.YES_NO_OPTION)!=JOptionPane.YES_OPTION)
            return;
        try{
            Files.writeString(dest.toPath(),latestNameCsv,StandardCharsets.UTF_8);
            status.setText("Saved CSV naming review only. No Ghidra symbols changed.");
        }catch(Exception ex){
            JOptionPane.showMessageDialog(this,"Cannot save CSV:\n"+ex.getMessage(),
                "Export error",JOptionPane.ERROR_MESSAGE);
        }
    }
    /**
     * Mutating action deliberately separate from the read-only analyzer.
     * Zero rows are preselected; only explicit checkmarks are applied. Ghidra
     * records changes in one undoable transaction.
     */
    private void reviewHardwareChanges(){
        Program program=plugin.getCurrentProgram();
        if(program==null || latestProgram!=program || latestMarkdown==null){
            status.setText("Run Hardware Analysis on this active program first.");
            return;
        }
        if(!latestConcrete){
            JOptionPane.showMessageDialog(this,
                "Only CPU32 was selected for the previous analysis.\n"+
                "Select 'MC68332 — user-selected device hypothesis' and rerun analysis\n"+
                "before creating device-specific memory blocks and register data.",
                "Concrete profile required",JOptionPane.WARNING_MESSAGE);
            return;
        }
        String vbrRaw=JOptionPane.showInputDialog(this,
            "VBR base address for an OPTIONAL 256 x 32-bit vector structure\n"+
            "(hexadecimal, 4-byte aligned; 000000 is only a candidate).\n"+
            "Leave the VBR structure unchecked if you are unsure.",
            "000000");
        if(vbrRaw==null)return;
        final List<HardwareApplyPlan.Item> proposals;
        try {
            String digits=vbrRaw.trim().replaceFirst("(?i)^0x","");
            proposals=HardwareApplyPlan.mc68332Mm1Candidates(
                Long.parseUnsignedLong(digits,16));
        }catch(Exception e){
            JOptionPane.showMessageDialog(this,"Invalid VBR address: "+e.getMessage(),
                "Invalid address",JOptionPane.WARNING_MESSAGE);
            return;
        }

        DefaultTableModel model=new DefaultTableModel(
            new Object[]{"Apply","Kind","Candidate","Range","Why / limitations"},0){
            @Override public Class<?> getColumnClass(int col){
                return col==0?Boolean.class:String.class;
            }
            @Override public boolean isCellEditable(int row,int col){return col==0;}
        };
        for(HardwareApplyPlan.Item item:proposals)
            model.addRow(new Object[]{false,item.kind.name(),item.name,
                item.location(),item.details});
        JTable table=new JTable(model);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.getColumnModel().getColumn(0).setPreferredWidth(55);
        table.getColumnModel().getColumn(1).setPreferredWidth(100);
        table.getColumnModel().getColumn(2).setPreferredWidth(230);
        table.getColumnModel().getColumn(3).setPreferredWidth(160);
        table.getColumnModel().getColumn(4).setPreferredWidth(580);
        JScrollPane scroll=new JScrollPane(table);
        scroll.setPreferredSize(new Dimension(960,420));

        JLabel warning=new JLabel("<html><b>Nothing selected by default.</b> "+
            "MC68332 and MM=1 are user-approved hypotheses, not detected facts.<br>"+
            "Blocks are uninitialized; occupied code/data/user labels are never cleared. "+
            "VBR is only typed if its full range is undefined.</html>");
        JPanel pane=new JPanel(new BorderLayout(5,5));
        pane.add(warning,BorderLayout.NORTH);
        pane.add(scroll,BorderLayout.CENTER);
        if(JOptionPane.showConfirmDialog(this,pane,
                "Review hardware definitions (Ghidra DB transaction / Undo)",
                JOptionPane.OK_CANCEL_OPTION,JOptionPane.PLAIN_MESSAGE)!=
                JOptionPane.OK_OPTION)return;
        List<HardwareApplyPlan.Item> accepted=new ArrayList<>();
        for(int i=0;i<model.getRowCount();i++)
            if(Boolean.TRUE.equals(model.getValueAt(i,0)))accepted.add(proposals.get(i));
        if(accepted.isEmpty()){
            status.setText("Nothing selected. No program changes.");
            return;
        }
        if(program!=plugin.getCurrentProgram()){
            status.setText("Active program changed; no definitions applied.");
            return;
        }
        int answer=JOptionPane.showConfirmDialog(this,
            "Apply "+accepted.size()+" selected definitions in one undoable "+
            "Ghidra transaction?\n"+
            "This will MODIFY the current Ghidra program database.\n"+
            "It does NOT modify the firmware binary on disk or connected hardware.\n"+
            "Never apply MC68332-specific labels without accepting that hypothesis.",
            "Final confirmation: write to Ghidra project",
            JOptionPane.YES_NO_OPTION,JOptionPane.WARNING_MESSAGE);
        if(answer!=JOptionPane.YES_OPTION)return;
        try{
            HardwareApplyService.Outcome outcome=HardwareApplyService.apply(program,accepted);
            StringBuilder sb=new StringBuilder();
            sb.append("Definitions applied: ").append(outcome.changed)
                .append("; safely skipped: ").append(outcome.skipped)
                .append("\n\n");
            for(String message:outcome.messages)sb.append(message).append("\n");
            JTextArea details=new JTextArea(sb.toString(),16,90);
            details.setEditable(false);
            JOptionPane.showMessageDialog(this,new JScrollPane(details),
                "Hardware definitions result — use Ghidra Undo to reverse",
                JOptionPane.INFORMATION_MESSAGE);
            status.setText(outcome.changed+" changed, "+outcome.skipped+
                " skipped. Rerun Hardware Analysis to refresh references and evidence.");
            ghidrassist.hardware.HardwareEvidenceCache.clear(program);
            latestMarkdown=null;latestNameCsv=null;
            approve.setEnabled(false);export.setEnabled(false);namePreview.setEnabled(false);
        }catch(Exception ex){
            ghidra.util.Msg.error(this,"Hardware definition transaction rolled back",ex);
            JOptionPane.showMessageDialog(this,
                "No definitions committed — the transaction was rolled back.\n"+
                ex.getClass().getSimpleName()+": "+ex.getMessage(),
                "Hardware definitions error",JOptionPane.ERROR_MESSAGE);
        }
    }

}
