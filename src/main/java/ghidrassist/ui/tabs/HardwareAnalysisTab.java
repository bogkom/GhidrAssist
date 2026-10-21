package ghidrassist.ui.tabs;

import ghidrassist.GhidrAssistPlugin;
import ghidrassist.hardware.HardwareInventoryService;
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
    private final JTextArea report=new JTextArea();
    private final JLabel status=new JLabel("Open a Ghidra program, then analyze candidate MCU registers.");
    private volatile String latestMarkdown;
    private volatile String latestNameCsv;
    private volatile Program latestProgram;

    public HardwareAnalysisTab(GhidrAssistPlugin plugin){
        super(new BorderLayout(5,5));
        this.plugin=plugin;
        JPanel controls=new JPanel(new FlowLayout(FlowLayout.LEFT,5,3));
        controls.add(new JLabel("Profile:"));
        controls.add(selection);
        controls.add(run);
        controls.add(export);
        controls.add(namePreview);
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
        int from=text.lastIndexOf('\\n',clicked)+1;
        int end=text.indexOf('\\n',clicked);
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
}
