package ghidrassist.ui.tabs;

import ghidrassist.GhidrAssistPlugin;
import ghidrassist.hardware.HardwareInventoryService;
import ghidra.program.model.listing.Program;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;
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
        report.setFont(new Font(Font.MONOSPACED,Font.PLAIN,12));
        report.setText(
            "Hardware Analysis (READ ONLY)\n\n"+
            "This tab scans existing Ghidra code references to candidate\n"+
            "MC68332 registers in both MM address maps.\n"+
            "The CPU32 language alone does not identify a physical MCU.\n"+
            "Reported chip-select windows are hypothetical and do not\n"+
            "authorize programming or scanning actual hardware.\n\n"+
            "No AI provider, API credits or online access are required.");
        add(controls,BorderLayout.NORTH);
        add(new JScrollPane(report),BorderLayout.CENTER);
        status.setBorder(BorderFactory.createEmptyBorder(4,8,5,8));
        add(status,BorderLayout.SOUTH);
        run.addActionListener(e->startScan());
        export.addActionListener(e->exportMarkdown());
        namePreview.addActionListener(e->exportNamingPreview());
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
                    report.setText(finished.markdown);
                    report.setCaretPosition(0);
                    export.setEnabled(true);
                    namePreview.setEnabled(true);
                    status.setText("Read-only: "+finished.uniqueSites+
                        " candidate sites in "+finished.functions+" functions. No database edits.");
                }catch(Exception ex){
                    report.setText("Hardware analysis failed:\n"+ex+"\n\nNo program changes.");
                    status.setText("Analysis failed; check Ghidra logs.");
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
