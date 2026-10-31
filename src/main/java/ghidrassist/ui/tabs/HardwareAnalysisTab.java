package ghidrassist.ui.tabs;

import ghidrassist.GhidrAssistPlugin;
import ghidrassist.hardware.HardwareInventoryService;
import ghidrassist.hardware.HardwareApplyPlan;
import ghidrassist.hardware.HardwareApplyService;
import ghidrassist.hardware.HardwareChangeProvenance;
import ghidrassist.hardware.HardwareFunctionNamingReview;
import ghidrassist.hardware.HardwareFunctionRenamePolicy;
import ghidrassist.hardware.HardwareFunctionRenameService;
import ghidrassist.core.MarkdownHelper;
import ghidra.app.services.GoToService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Color;
import java.awt.event.KeyEvent;
import java.awt.event.InputEvent;
import javax.swing.AbstractAction;
import javax.swing.JComponent;
import javax.swing.KeyStroke;
import javax.swing.UIManager;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.BadLocationException;
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
import javax.swing.JTabbedPane;
import javax.swing.SwingWorker;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JCheckBox;
import javax.swing.table.DefaultTableModel;
import java.awt.Dimension;
import java.awt.Dialog;
import java.awt.Window;
import java.awt.Toolkit;
import javax.swing.JDialog;
import javax.swing.SwingUtilities;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.event.DocumentListener;
import javax.swing.event.DocumentEvent;
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
    private final JButton run=new JButton("Analyze");
    private final JButton cancelScan=new JButton("Cancel Analyze");
    private final JButton export=new JButton("Export MD");
    private final JButton namePreview=new JButton("Export CSV");
    private final JButton exportConfigCsv=new JButton("Evidence CSV...");
    private final JButton approve=new JButton("Review / Apply...");
    private final JButton exploreMmio=new JButton("MMIO accesses...");
    private final JButton reviewNames=new JButton("Review names...");
    private final JButton previewProfile=new JButton("Preview profile...");
    private final JTextArea report=new JTextArea();
    private final JTextArea overview=new JTextArea();
    private final JTabbedPane reportTabs=new JTabbedPane();
    private final JTextField reportSearch=new JTextField(21);
    private final JButton previousHit=new JButton("Previous");
    private final JButton nextHit=new JButton("Next");
    private final JCheckBox matchCase=new JCheckBox("Aa");
    private final JLabel searchCount=new JLabel("0 matches");
    private final List<int[]> reportHits=new ArrayList<>();
    private int hitIndex=-1;
    private final JLabel status=new JLabel("Open a Ghidra program, then analyze candidate MCU registers.");
    private volatile String latestMarkdown;
    private volatile String latestNameCsv;
    private volatile String latestConfigCsv;
    private volatile Program latestProgram;
    private volatile ghidrassist.hardware.HardwareAnalysisRevision latestRevision;
    private volatile ghidra.util.task.TaskMonitorAdapter activeMonitor;
    private volatile boolean latestConcrete;
    private volatile List<HardwareFunctionNamingReview.Proposal> latestFunctionProposals=List.of();
    private volatile List<HardwareInventoryService.Site> latestSites=List.of();
    private volatile ghidrassist.hardware.HardwareCsbarUnifiedReview.Review latestCsbarReview;

    public HardwareAnalysisTab(GhidrAssistPlugin plugin){
        super(new BorderLayout(5,5));
        this.plugin=plugin;
        // Two compact rows remain usable in narrow docked Ghidra windows.
        JPanel controls=new JPanel(new BorderLayout(0,2));
        JPanel profileRow=new JPanel(new FlowLayout(FlowLayout.LEFT,5,1));
        profileRow.add(new JLabel("Profile:"));
        profileRow.add(selection);
        profileRow.add(reviewNames);
        profileRow.add(previewProfile);
        profileRow.add(exportConfigCsv);
        JPanel actionRow=new JPanel(new FlowLayout(FlowLayout.LEFT,5,1));
        actionRow.add(run);
        actionRow.add(cancelScan);
        actionRow.add(approve);
        actionRow.add(exploreMmio);
        actionRow.add(export);
        actionRow.add(namePreview);
        controls.add(profileRow,BorderLayout.NORTH);
        controls.add(actionRow,BorderLayout.CENTER);
        JPanel searchRow=new JPanel(new FlowLayout(FlowLayout.LEFT,5,1));
        searchRow.add(new JLabel("Find:"));
        searchRow.add(reportSearch);
        searchRow.add(previousHit);
        searchRow.add(nextHit);
        matchCase.setToolTipText("Case-sensitive report search");
        searchRow.add(matchCase);
        searchRow.add(searchCount);
        controls.add(searchRow,BorderLayout.SOUTH);
        reportSearch.setToolTipText("Find registers, function names, addresses or values. Ctrl+F to focus.");
        reportSearch.getDocument().addDocumentListener(new DocumentListener(){
            public void insertUpdate(DocumentEvent e){updateReportSearch();}
            public void removeUpdate(DocumentEvent e){updateReportSearch();}
            public void changedUpdate(DocumentEvent e){updateReportSearch();}
        });
        reportSearch.addActionListener(e->stepReportSearch(1));
        matchCase.addActionListener(e->updateReportSearch());
        previousHit.addActionListener(e->stepReportSearch(-1));
        nextHit.addActionListener(e->stepReportSearch(1));
        reportSearch.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER,InputEvent.SHIFT_DOWN_MASK),"previousHit");
        reportSearch.getActionMap().put("previousHit",new AbstractAction(){
            @Override public void actionPerformed(java.awt.event.ActionEvent e){stepReportSearch(-1);}
        });
        getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
            .put(KeyStroke.getKeyStroke(KeyEvent.VK_F,InputEvent.CTRL_DOWN_MASK),"focusReportFind");
        getActionMap().put("focusReportFind",new AbstractAction(){
            @Override public void actionPerformed(java.awt.event.ActionEvent e){
                reportSearch.requestFocusInWindow();
                reportSearch.selectAll();
            }
        });
        run.setToolTipText("Scan the currently active Ghidra program (read-only)");
        approve.setToolTipText("Review proposed memory regions/registers and apply selected items in an undoable transaction");
        export.setToolTipText("Export Hardware Evidence as Markdown for RAG");
        namePreview.setToolTipText("Export review-only hardware label suggestions as CSV");
        exportConfigCsv.setToolTipText("Source-only CFG MMIO receipts, never naming/Apply commands");
        approve.setEnabled(false);
        cancelScan.setEnabled(false);
        reviewNames.setEnabled(false);
        reviewNames.setToolTipText("Review function role names and apply explicitly approved, collision-free proposals in one Undo transaction");
        export.setEnabled(false);exportConfigCsv.setEnabled(false);
        namePreview.setEnabled(false);
        exportConfigCsv.setEnabled(false);
        report.setEditable(false);
        overview.setEditable(false);
        overview.setText("Run Analyze to see a three-part, read-only summary.\n"+
            "Full source references and conditional tables appear on the Full evidence tab.");
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
        reportTabs.addTab("Overview",new JScrollPane(overview));
        reportTabs.addTab("Full evidence",new JScrollPane(report));
        reportTabs.setSelectedIndex(0);
        add(reportTabs,BorderLayout.CENTER);
        status.setBorder(BorderFactory.createEmptyBorder(4,8,5,8));
        add(status,BorderLayout.SOUTH);
        run.addActionListener(e->startScan());
        cancelScan.addActionListener(e->{
            ghidra.util.task.TaskMonitorAdapter m=activeMonitor;
            if(m!=null){
                m.cancel();
                cancelScan.setEnabled(false);
                status.setText("Cancellation requested; completed CFG checkpoint may be reused.");
            }
        });
        export.addActionListener(e->exportMarkdown());
        namePreview.addActionListener(e->exportNamingPreview());
        exportConfigCsv.addActionListener(e->exportConfigurationEvidence());
        approve.addActionListener(e->reviewHardwareChanges());
        exploreMmio.addActionListener(e->showMmioExplorer());
        reviewNames.addActionListener(e->reviewFunctionNames());
        previewProfile.addActionListener(e->previewExternalProfile());
        selection.addActionListener(e->{
            if(latestRevision!=null && !currentScan())
                discardStale("MCU profile selection changed; previous evidence invalidated.");
        });
    }

    /**
     * Preview only. This input is never converted to a Ghidra Register,
     * HardwareProfiles.Profile or Review/Apply item.
     */
    private void previewExternalProfile(){
        JFileChooser chooser=new JFileChooser();
        chooser.setDialogTitle("Preview external MCU profile manifest — no import");
        chooser.setFileFilter(new FileNameExtensionFilter("Profile manifest (*.tsv)","tsv"));
        if(chooser.showOpenDialog(this)!=JFileChooser.APPROVE_OPTION)return;
        File file=chooser.getSelectedFile();
        try{
            if(!file.isFile() || Files.size(file.toPath())>
                    ghidrassist.hardware.HardwareProfileManifestPreview.MAX_BYTES)
                throw new IllegalArgumentException("Profile must be a local TSV file no larger than 1 MiB");
            String data=Files.readString(file.toPath(),StandardCharsets.UTF_8);
            var result=ghidrassist.hardware.HardwareProfileManifestPreview.parse(data);
            JTextArea preview=new JTextArea(result.report(),22,91);
            preview.setEditable(false);
            preview.setCaretPosition(0);
            int selected=JOptionPane.showOptionDialog(this,
                new JScrollPane(preview),
                "Structural preview ONLY — no MCU profile imported",
                JOptionPane.DEFAULT_OPTION,JOptionPane.INFORMATION_MESSAGE,
                null,new Object[]{"Close preview","Compare with another..."},
                "Close preview");
            if(selected==1){
                JFileChooser otherChooser=new JFileChooser();
                otherChooser.setDialogTitle(
                    "Compare second untrusted MCU profile manifest — no import");
                otherChooser.setFileFilter(new FileNameExtensionFilter(
                    "Profile manifest (*.tsv)","tsv"));
                if(otherChooser.showOpenDialog(this)==JFileChooser.APPROVE_OPTION){
                    File other=otherChooser.getSelectedFile();
                    if(!other.isFile() || Files.size(other.toPath())>
                            ghidrassist.hardware.HardwareProfileManifestPreview.MAX_BYTES)
                        throw new IllegalArgumentException(
                            "Second profile must be a local TSV file no larger than 1 MiB");
                    String otherText=Files.readString(other.toPath(),
                        StandardCharsets.UTF_8);
                    var parsedOther=ghidrassist.hardware.HardwareProfileManifestPreview.parse(otherText);
                    var comparison=ghidrassist.hardware.HardwareProfileManifestComparison
                        .compare(result,parsedOther);
                    JTextArea differences=new JTextArea(comparison.render(),24,94);
                    differences.setEditable(false);
                    differences.setCaretPosition(0);
                    JOptionPane.showMessageDialog(this,new JScrollPane(differences),
                        "Unverified manifest differences — read-only",
                        JOptionPane.INFORMATION_MESSAGE);
                }
            }
            // An explicit local checksum check is optional. Source identity
            // claims are not silently promoted by previewing metadata.
            String claimed=result.source().claimedSha256();
            if(claimed.matches("[a-fA-F0-9]{64}") &&
                    JOptionPane.showConfirmDialog(this,
                        "Optionally verify a LOCAL PDF against the claimed SHA-256?"+
                        "\nThis does NOT verify edition, page labels or MCU identity.",
                        "Verify local document bytes",JOptionPane.YES_NO_OPTION,
                        JOptionPane.QUESTION_MESSAGE)==JOptionPane.YES_OPTION){
                JFileChooser pdfChooser=new JFileChooser();
                pdfChooser.setDialogTitle("Select local PDF for SHA-256 comparison");
                pdfChooser.setFileFilter(
                    new FileNameExtensionFilter("PDF document (*.pdf)","pdf"));
                if(pdfChooser.showOpenDialog(this)==JFileChooser.APPROVE_OPTION){
                    File pdf=pdfChooser.getSelectedFile();
                    try{
                        if(!pdf.isFile() || Files.size(pdf.toPath())>
                                ghidrassist.hardware.HardwareProfilePdfHashCheck.MAX_PDF_BYTES)
                            throw new IllegalArgumentException(
                                "Local PDF missing or exceeds 128 MiB");
                        ghidrassist.hardware.HardwareProfilePdfHashCheck.Result checked;
                        try(var in=Files.newInputStream(pdf.toPath())){
                            checked=ghidrassist.hardware.HardwareProfilePdfHashCheck
                                .verify(in,claimed,
                                  ghidrassist.hardware.HardwareProfilePdfHashCheck.MAX_PDF_BYTES);
                        }
                        JOptionPane.showMessageDialog(this,checked.report(),
                            "Claimed PDF checksum comparison",JOptionPane.INFORMATION_MESSAGE);
                    }catch(Exception error){
                        JOptionPane.showMessageDialog(this,
                            "Could not verify local PDF: "+error.getMessage(),
                            "PDF identity UNKNOWN",JOptionPane.WARNING_MESSAGE);
                    }
                }
            }
            status.setText("Manifest preview completed: no Ghidra changes; manual facts unverified.");
        }catch(Exception ex){
            JOptionPane.showMessageDialog(this,
                "Profile rejected (no changes):\n"+ex.getMessage(),
                "Unsafe or invalid manifest",JOptionPane.WARNING_MESSAGE);
            status.setText("Manifest rejected; current MCU profile unchanged.");
        }
    }

    /** Uses the very same saved settings as Settings > Response Appearance. */
    public void refreshAppearance(){
        String family=MarkdownHelper.getResponseFontFamily();
        int size=MarkdownHelper.getResponseFontSize();
        Font configured=new Font(family==null?Font.MONOSPACED:family,Font.PLAIN,size);
        report.setFont(configured);
        overview.setFont(configured);
    }
    private void updateReportSearch(){
        if(!reportSearch.getText().isEmpty())
            reportTabs.setSelectedIndex(1);
        reportHits.clear();
        hitIndex=-1;
        report.getHighlighter().removeAllHighlights();
        String needle=reportSearch.getText();
        String text=report.getText();
        if(needle!=null && !needle.isEmpty()){
            String haystack=matchCase.isSelected()?text:text.toLowerCase(java.util.Locale.ROOT);
            String query=matchCase.isSelected()?needle:needle.toLowerCase(java.util.Locale.ROOT);
            int at=0;
            while((at=haystack.indexOf(query,at))>=0){
                reportHits.add(new int[]{at,at+needle.length()});
                try{
                    // Avoid rendering thousands of Swing highlight shapes at once.
                    if(reportHits.size()<=2000)
                        report.getHighlighter().addHighlight(at,at+needle.length(),
                            new DefaultHighlighter.DefaultHighlightPainter(new Color(255,228,125)));
                }catch(BadLocationException ignored){}
                at+=Math.max(1,query.length());
            }
        }
        updateSearchCount();
    }
    private void updateSearchCount(){
        int total=reportHits.size();
        searchCount.setText(total==0?"0 matches":
            ((hitIndex<0?0:hitIndex+1)+" / "+total+
            (total>2000?" (first 2000 highlighted)":"")));
        previousHit.setEnabled(total>0);
        nextHit.setEnabled(total>0);
    }
    private void stepReportSearch(int delta){
        if(reportHits.isEmpty())return;
        hitIndex=Math.floorMod(hitIndex+delta,reportHits.size());
        int offset=reportHits.get(hitIndex)[0];
        report.setCaretPosition(offset);
        try{
            java.awt.geom.Rectangle2D r=report.modelToView2D(offset);
            if(r!=null)report.scrollRectToVisible(r.getBounds());
        }catch(BadLocationException ignored){}
        updateSearchCount();
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
            if(program==null || !currentScan()){
                status.setText("Program revision changed; rerun Hardware Analysis before navigating.");
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
    /** Source hash is Ghidra's original import metadata, not edited content. */
    private static ghidrassist.hardware.HardwareAnalysisRevision revision(
            Program program,boolean concrete) {
        return ghidrassist.hardware.HardwareAnalysisRevision.capture(
            program,program.getModificationNumber(),program.getLanguageID().toString(),
            program.getExecutableSHA256(),concrete);
    }

    private boolean currentScan() {
        Program active=plugin.getCurrentProgram();
        if(active==null || latestRevision==null || latestProgram!=active ||
                latestConcrete!=(selection.getSelectedIndex()==1))return false;
        return latestRevision.matches(active,active.getModificationNumber(),
            active.getLanguageID().toString(),active.getExecutableSHA256(),
            latestConcrete);
    }

    private void discardStale(String reason) {
        Program old=latestProgram;
        if(old!=null){
            ghidrassist.hardware.HardwareEvidenceCache.clear(old);
            ghidrassist.hardware.HardwareFlowStageCache.clear(old);
        }
        latestMarkdown=null;latestConfigCsv=null;
        latestNameCsv=null;
        latestProgram=null;
        latestRevision=null;
        latestFunctionProposals=List.of();
        latestSites=List.of();
        latestCsbarReview=null;
        approve.setEnabled(false);
        reviewNames.setEnabled(false);
        export.setEnabled(false);exportConfigCsv.setEnabled(false);
        namePreview.setEnabled(false);
        report.setText(reason+"\nNo results were published to AI/RAG. Rerun Analyze.");
        status.setText(reason);
    }

    private void showMmioExplorer(){
        Program program=plugin.getCurrentProgram();
        if(program==null || !currentScan() || latestMarkdown==null){
            status.setText("Program changed; rerun Analyze before opening MMIO accesses.");
            return;
        }
        List<ghidrassist.hardware.HardwareMmioExplorer.Observation> raw=new ArrayList<>();
        for(HardwareInventoryService.Site site:latestSites){
            raw.add(new ghidrassist.hardware.HardwareMmioExplorer.Observation(
                site.pc.getOffset(),site.registerAddress,site.register,site.function,
                site.asm,site.write,site.literal));
        }
        final List<ghidrassist.hardware.HardwareMmioExplorer.Row> rows=
            ghidrassist.hardware.HardwareMmioExplorer.rows(raw,latestConcrete);
        final List<ghidrassist.hardware.HardwareMmioExplorer.Row> visible=new ArrayList<>();
        DefaultTableModel model=new DefaultTableModel(
            new Object[]{"PC","Register","MMIO address","Access","Literal word",
                "Evidence quality","Function","Instruction","Profile scope"},0){
            @Override public boolean isCellEditable(int row,int column){return false;}
        };
        JTable table=new JTable(model);
        table.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setRowHeight(Math.max(25,table.getFont().getSize()+8));
        int[] widths={125,120,125,150,110,350,190,350,270};
        for(int i=0;i<widths.length;i++)
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        JTextField search=new JTextField(30);
        JLabel count=new JLabel();
        Runnable refill=()->{
            visible.clear();
            model.setRowCount(0);
            for(var candidate:rows){
                if(!candidate.matches(search.getText()))continue;
                visible.add(candidate);
                model.addRow(new Object[]{candidate.pcHex(),candidate.register(),
                    candidate.addressHex(),candidate.access(),candidate.value(),
                    candidate.evidence(),candidate.function(),candidate.instruction(),
                    candidate.deviceScope()});
            }
            count.setText(visible.size()+" / "+rows.size()+" reference site(s)");
        };
        search.getDocument().addDocumentListener(new DocumentListener(){
            public void insertUpdate(DocumentEvent e){refill.run();}
            public void removeUpdate(DocumentEvent e){refill.run();}
            public void changedUpdate(DocumentEvent e){refill.run();}
        });
        refill.run();

        Window owner=SwingUtilities.getWindowAncestor(this);
        JDialog dialog=new JDialog(owner,"MMIO access references — read-only",
            Dialog.ModalityType.MODELESS);
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        JLabel explanation=new JLabel("<html>Ghidra static references, not a runtime trace. "+
            "Only literal complete word writes have a known candidate value; "+
            "CPU32 survey does not establish MC68332 identity. No project edits.</html>");
        JPanel top=new JPanel(new BorderLayout(4,4));
        explanation.setBorder(BorderFactory.createEmptyBorder(7,8,6,8));
        top.add(explanation,BorderLayout.NORTH);
        JPanel filters=new JPanel(new FlowLayout(FlowLayout.LEFT,8,3));
        filters.add(new JLabel("Filter:"));filters.add(search);filters.add(count);
        top.add(filters,BorderLayout.SOUTH);

        JButton go=new JButton("Go To Listing");
        JButton close=new JButton("Close");
        Runnable navigate=()->{
            if(!currentScan()){
                count.setText("Active program changed; rerun Analyze.");
                return;
            }
            int selected=table.getSelectedRow();
            if(selected<0 || selected>=visible.size()){
                count.setText("Select an instruction before navigation.");
                return;
            }
            long pc=visible.get(selected).pc();
            try{
                Address address=program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(pc);
                GoToService service=plugin.getTool().getService(GoToService.class);
                if(service==null || !service.goTo(address,program))
                    count.setText("Cannot navigate to "+address);
                else status.setText("Listing: "+address);
            }catch(Exception ex){count.setText("Navigation error: "+ex.getMessage());}
        };
        go.addActionListener(e->navigate.run());
        close.addActionListener(e->dialog.dispose());
        table.addMouseListener(new MouseAdapter(){
            @Override public void mouseClicked(MouseEvent event){
                if(event.getClickCount()==2 && table.getSelectedRow()>=0)
                    navigate.run();
            }
        });
        JPanel footer=new JPanel(new FlowLayout(FlowLayout.RIGHT,8,4));
        footer.add(go);footer.add(close);
        JPanel panel=new JPanel(new BorderLayout(5,5));
        panel.add(top,BorderLayout.NORTH);
        panel.add(new JScrollPane(table),BorderLayout.CENTER);
        panel.add(footer,BorderLayout.SOUTH);
        panel.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
        dialog.setContentPane(panel);
        dialog.setMinimumSize(new Dimension(640,380));
        Dimension screen=Toolkit.getDefaultToolkit().getScreenSize();
        dialog.setSize(Math.min(1330,screen.width-70),
            Math.min(780,screen.height-90));
        dialog.setLocationRelativeTo(this);
        dialog.setResizable(true);
        dialog.setVisible(true);
    }

    private void startScan(){
        final Program program=plugin.getCurrentProgram();
        if(program==null){
            JOptionPane.showMessageDialog(this,"Open a program in CodeBrowser first.",
                "Hardware analysis",JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        final boolean concrete=selection.getSelectedIndex()==1;
        // Incremental reuse is only for a completed scan of this exact
        // in-memory revision. A changed/undone program is always rescanned.
        if(currentScan() && latestMarkdown!=null){
            status.setText("Unchanged Ghidra revision: reusing current read-only results.");
            return;
        }
        final ghidrassist.hardware.HardwareAnalysisRevision started=
            revision(program,concrete);
        final ghidra.util.task.TaskMonitorAdapter monitor=
            new ghidra.util.task.TaskMonitorAdapter(true);
        activeMonitor=monitor;
        cancelScan.setEnabled(true);
        run.setEnabled(false);export.setEnabled(false);exportConfigCsv.setEnabled(false);namePreview.setEnabled(false);
        exploreMmio.setEnabled(false);
        approve.setEnabled(false);
        reviewNames.setEnabled(false);
        latestFunctionProposals=List.of();
        latestSites=List.of();
        latestCsbarReview=null;
        latestMarkdown=null;latestConfigCsv=null;latestNameCsv=null;latestProgram=null;
        latestRevision=null;
        ghidrassist.hardware.HardwareEvidenceCache.clear(program);
        report.getHighlighter().removeAllHighlights();
        reportHits.clear();
        updateSearchCount();
        overview.setText("Analyzing hardware...\nRead-only evidence scan in progress.");
        reportTabs.setSelectedIndex(0);
        report.setText("Analyzing hardware...\nScanning references and memory regions.\n"+
            "This is a read-only scan; no project data is modified.");
        report.setCaretPosition(0);
        status.setText("Scanning references and disassembled instructions. Read-only.");
        SwingWorker<HardwareInventoryService.Report,Void> worker=
                new SwingWorker<>() {
            @Override protected HardwareInventoryService.Report doInBackground()throws Exception{
                return new HardwareInventoryService().scan(program,concrete,
                    monitor,started);
            }
            @Override protected void done(){
                activeMonitor=null;
                cancelScan.setEnabled(false);
                run.setEnabled(true);
                try {
                    HardwareInventoryService.Report finished=get();
                    if(plugin.getCurrentProgram()!=program ||
                            selection.getSelectedIndex()!=(concrete?1:0) ||
                            !started.matches(program,program.getModificationNumber(),
                                program.getLanguageID().toString(),
                                program.getExecutableSHA256(),concrete) ||
                            !ghidrassist.hardware.HardwareEvidenceCache.publishIfCurrent(
                                program,finished.markdown,started)){
                        discardStale("Program revision or MCU selection changed during analysis.");
                        return;
                    }
                    latestMarkdown=finished.markdown;
                    latestNameCsv=finished.namePreviewCsv;
                    latestConfigCsv=finished.configurationEvidenceCsv;
                    latestProgram=program;
                    latestRevision=started;
                    latestConcrete=concrete;
                    latestFunctionProposals=finished.functionProposals;
                    latestSites=finished.sites;
                    latestCsbarReview=finished.csbarReview;
                    exploreMmio.setEnabled(!latestSites.isEmpty());
                    approve.setEnabled(true);
                    reviewNames.setEnabled(concrete && latestFunctionProposals.stream()
                        .anyMatch(p->p.status==ghidrassist.hardware.HardwareNamingReview.Status.REVIEW_REQUIRED));
                    overview.setText(finished.overviewMarkdown);
                    overview.setCaretPosition(0);
                    report.setText(finished.detailsMarkdown);
                    report.setCaretPosition(0);
                    reportTabs.setSelectedIndex(0);
                    updateReportSearch();
                    export.setEnabled(true);
                    namePreview.setEnabled(true);
                    exportConfigCsv.setEnabled(true);
                    status.setText("Read-only: "+finished.uniqueSites+
                        " candidate sites in "+finished.functions+" functions. No database edits.");
                }catch(Exception ex){
                    Throwable root=ex;
                    while(root.getCause()!=null && root.getCause()!=root)
                        root=root.getCause();
                    if(root instanceof ghidra.util.exception.CancelledException ||
                            monitor.isCancelled() ||
                            ex instanceof java.util.concurrent.CancellationException){
                        discardStale("Hardware Analyze canceled. Completed same-revision CFG stage retained.");
                        return;
                    }
                    ghidra.util.Msg.error(HardwareAnalysisTab.this,
                        "Hardware Analysis failed; detailed stack trace follows",ex);
                    overview.setText("Hardware analysis failed. See Full evidence and Ghidra Application Log.");
                    reportTabs.setSelectedIndex(1);
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
        if(latestMarkdown==null || !currentScan()){
            export.setEnabled(false);exportConfigCsv.setEnabled(false);
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
    /** Local CSV for evidence only; not compatible with Apply proposal schema. */
    private void exportConfigurationEvidence(){
        if(latestConfigCsv==null || !currentScan()){
            exportConfigCsv.setEnabled(false);
            status.setText("Program changed; rerun Analyze before evidence export.");
            return;
        }
        JFileChooser chooser=new JFileChooser();
        chooser.setDialogTitle("Source-only CFG evidence — NEVER_AUTO_APPLY");
        chooser.setFileFilter(new FileNameExtensionFilter("Static evidence CSV (*.csv)","csv"));
        chooser.setSelectedFile(new File("GhidrAssist_CFG_MMIO_Evidence.csv"));
        if(chooser.showSaveDialog(this)!=JFileChooser.APPROVE_OPTION)return;
        File dest=chooser.getSelectedFile();
        if(!dest.getName().toLowerCase(java.util.Locale.ROOT).endsWith(".csv"))
            dest=new File(dest.getParentFile(),dest.getName()+".csv");
        if(!currentScan()){
            exportConfigCsv.setEnabled(false);
            status.setText("Program changed while choosing path; stale evidence not saved.");
            return;
        }
        if(dest.isFile() && JOptionPane.showConfirmDialog(this,
                "Replace existing evidence CSV?\n"+dest.getAbsolutePath(),
                "Confirm export",JOptionPane.YES_NO_OPTION)!=JOptionPane.YES_OPTION)
            return;
        if(!currentScan()){
            exportConfigCsv.setEnabled(false);
            status.setText("Program changed before CSV export; no stale file saved.");
            return;
        }
        try{
            Files.writeString(dest.toPath(),latestConfigCsv,StandardCharsets.UTF_8);
            status.setText("Static CFG evidence saved locally. No Ghidra changes.");
        }catch(Exception ex){
            JOptionPane.showMessageDialog(this,
                "Cannot save evidence CSV:\n"+ex.getMessage(),
                "Export error",JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportNamingPreview(){
        if(latestNameCsv==null || !currentScan()){
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
     * Separate, opt-in function naming approval, keeping the Memory Review
     * unaffected. Preflight is rechecked under a single undoable transaction.
     */
    private void reviewFunctionNames() {
        final Program program=plugin.getCurrentProgram();
        if(program==null || !currentScan() || latestMarkdown==null ||
                !latestConcrete) {
            status.setText("Choose MC68332 and analyze the active program before reviewing names.");
            return;
        }
        final List<HardwareFunctionNamingReview.Proposal> proposals=
            List.copyOf(latestFunctionProposals);
        if(proposals.isEmpty()){
            status.setText("No function role naming candidates in current analysis.");
            return;
        }
        final List<HardwareFunctionRenamePolicy.Decision> decisions=new ArrayList<>();
        for(var p:proposals)
            decisions.add(HardwareFunctionRenameService.preflight(program,p));

        DefaultTableModel model=new DefaultTableModel(new Object[]{
            "Apply","Status","Function address","Current name",
            "Proposed name","Write evidence / role"},0){
            @Override public Class<?> getColumnClass(int col) {
                return col==0?Boolean.class:String.class;
            }
            @Override public boolean isCellEditable(int row,int col) {
                return col==0 &&
                    decisions.get(row)==HardwareFunctionRenamePolicy.Decision.READY;
            }
        };
        for(int i=0;i<proposals.size();i++) {
            var p=proposals.get(i);
            boolean ready=decisions.get(i)==HardwareFunctionRenamePolicy.Decision.READY;
            model.addRow(new Object[]{ready,decisions.get(i).name(),
                String.format("0x%08X",p.functionAddress),p.currentName,
                p.proposedName,p.writeSites+" sites; "+p.role+"; "+p.registers});
        }
        JTable table=new JTable(model);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setRowHeight(Math.max(25,table.getFont().getSize()+9));
        int[] sizes={62,175,150,205,410,490};
        for(int i=0;i<sizes.length;i++)
            table.getColumnModel().getColumn(i).setPreferredWidth(sizes[i]);
        JPanel content=new JPanel(new BorderLayout(6,6));
        content.setBorder(BorderFactory.createEmptyBorder(7,7,7,7));
        content.add(new JLabel("<html><b>Candidate function names — MC68332 hypothesis</b>"+
            "<br>Only Ghidra-generated function names and multi-register direct writes "+
            "are eligible. Collisions/stale names are blocked. No change until final confirmation.</html>"),
            BorderLayout.NORTH);
        content.add(new JScrollPane(table),BorderLayout.CENTER);
        JButton selectSafe=new JButton("Select applicable");
        JButton clear=new JButton("Clear selection");
        JButton apply=new JButton("Apply selected...");
        JButton cancel=new JButton("Cancel");
        JLabel total=new JLabel();
        Runnable refresh=()->{
            int selected=0;
            for(int i=0;i<model.getRowCount();i++)
                if(Boolean.TRUE.equals(model.getValueAt(i,0)))selected++;
            total.setText(selected+" function(s) selected");
        };
        model.addTableModelListener(e->refresh.run());
        refresh.run();
        selectSafe.addActionListener(e->{
            for(int i=0;i<proposals.size();i++)
                model.setValueAt(decisions.get(i)==HardwareFunctionRenamePolicy.Decision.READY,i,0);
        });
        clear.addActionListener(e->{
            for(int i=0;i<proposals.size();i++)model.setValueAt(false,i,0);
        });
        JPanel actions=new JPanel(new FlowLayout(FlowLayout.LEFT,7,5));
        actions.add(selectSafe);actions.add(clear);actions.add(total);
        actions.add(apply);actions.add(cancel);
        content.add(actions,BorderLayout.SOUTH);
        Window owner=SwingUtilities.getWindowAncestor(this);
        JDialog dialog=new JDialog(owner,"Review function name candidates",
            Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        dialog.setContentPane(content);
        Dimension screen=Toolkit.getDefaultToolkit().getScreenSize();
        dialog.setSize(Math.min(1240,Math.max(740,screen.width-100)),
            Math.min(740,Math.max(470,screen.height-130)));
        dialog.setMinimumSize(new Dimension(720,420));
        dialog.setResizable(true);
        dialog.setLocationRelativeTo(this);
        List<HardwareFunctionNamingReview.Proposal> selected=new ArrayList<>();
        cancel.addActionListener(e->dialog.dispose());
        apply.addActionListener(e->{
            if(table.isEditing())table.getCellEditor().stopCellEditing();
            selected.clear();
            for(int i=0;i<proposals.size();i++){
                if(!Boolean.TRUE.equals(model.getValueAt(i,0)))continue;
                if(decisions.get(i)!=HardwareFunctionRenamePolicy.Decision.READY){
                    JOptionPane.showMessageDialog(dialog,
                        "This function is no longer eligible for renaming.",
                        "Preflight blocked",JOptionPane.WARNING_MESSAGE);
                    return;
                }
                selected.add(proposals.get(i));
            }
            if(selected.isEmpty()){
                JOptionPane.showMessageDialog(dialog,"No functions selected.",
                    "Naming review",JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            dialog.dispose();
        });
        dialog.setVisible(true);
        if(selected.isEmpty())return;
        if(!currentScan()){
            status.setText("Program revision changed; no functions renamed.");
            return;
        }
        int confirm=JOptionPane.showConfirmDialog(this,
            "Rename "+selected.size()+" function(s) in ONE undoable transaction?\n"+
            "Names remain explicit MC68332 CANDIDATES, not hardware identification.\n"+
            "Stale function names or symbol collisions abort the entire transaction.\n"+
            "No bytes or external devices are modified.",
            "Final confirmation — change Ghidra function names",
            JOptionPane.YES_NO_OPTION,JOptionPane.WARNING_MESSAGE);
        if(confirm!=JOptionPane.YES_OPTION)return;
        try{
            var outcome=HardwareFunctionRenameService.apply(program,selected);
            JOptionPane.showMessageDialog(this,
                "Renamed "+outcome.renamed()+" function(s). Ghidra Undo is available.\n"+
                "Rerun Hardware Analysis to regenerate evidence.",
                "Function names updated",JOptionPane.INFORMATION_MESSAGE);
            status.setText(outcome.renamed()+" function names applied (undoable). Reanalyze.");
            ghidrassist.hardware.HardwareEvidenceCache.clear(program);
            latestProgram=null;latestMarkdown=null;latestConfigCsv=null;latestNameCsv=null;
            latestRevision=null;
            latestFunctionProposals=List.of();
            reviewNames.setEnabled(false);approve.setEnabled(false);
            export.setEnabled(false);exportConfigCsv.setEnabled(false);namePreview.setEnabled(false);
        }catch(Exception ex){
            ghidra.util.Msg.error(this,"Reviewed function rename failed and rolled back",ex);
            JOptionPane.showMessageDialog(this,
                "No function names committed; entire transaction rolled back.\n"+
                ex.getClass().getSimpleName()+": "+ex.getMessage(),
                "Rename error",JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Mutating action deliberately separate from the read-only analyzer.
     * Zero rows are preselected; only explicit checkmarks are applied. Ghidra
     * records changes in one undoable transaction.
     */
    /**
     * Resizable review dialog. The user already selected a concrete MCU
     * hypothesis; preflight automatically checks only genuinely safe,
     * actionable rows. Conflicts, existing work, external peripherals,
     * relocated RAM and unverified VBR are unchecked.
     */
    private List<HardwareApplyPlan.CsbarEvidence> csbarEvidence(){
        // Do not regenerate a less-conservative Listing-only proposal set.
        // Only the current completed, revision-bound reconciled CFG+Listing
        // evidence may reach Review/Apply.
        var reviewed=latestCsbarReview;
        if(!currentScan() || !latestConcrete || reviewed==null)return List.of();
        List<HardwareApplyPlan.CsbarEvidence> candidates=new ArrayList<>();
        for(var proposed:reviewed.candidates())
            candidates.add(new HardwareApplyPlan.CsbarEvidence(
                proposed.register(),proposed.word(),proposed.origin()));
        return List.copyOf(candidates);
    }

    /**
     * Snapshot of Ghidra primary symbol source type, not an actor audit trail.
     * No read from original firmware bytes and no SymbolTable modifications.
     */
    private static HardwareChangeProvenance.ReviewRow provenanceRow(Program program,
            HardwareApplyPlan.Item item,HardwareApplyService.Decision decision,
            boolean selected) {
        String existing=null;
        String sourceType=null;
        if(item.kind==HardwareApplyPlan.Kind.REGISTER ||
                item.kind==HardwareApplyPlan.Kind.ANNOTATION){
            try {
                Address location=program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(item.address);
                Symbol primary=program.getSymbolTable().getPrimarySymbol(location);
                if(primary!=null){
                    existing=primary.getName();
                    if(primary.getSource()!=null)
                        sourceType=primary.getSource().name();
                }
            }catch(RuntimeException addressNotResolvable){
                // The inability to inspect a symbol is UNKNOWN, never no symbol.
                sourceType="UNKNOWN";
            }
        }
        return new HardwareChangeProvenance.ReviewRow(item.kind.name(),
            item.location(),item.name,existing,sourceType,decision.state.name(),
            selected,decision.description+"; "+item.details);
    }

    private void reviewHardwareChanges(){
        Program program=plugin.getCurrentProgram();
        if(program==null || !currentScan() || latestMarkdown==null){
            status.setText("Run Hardware Analysis on the current program revision first.");
            return;
        }
        if(!latestConcrete){
            JOptionPane.showMessageDialog(this,
                "Select the MC68332 profile and rerun Analyze before"+
                " approving MCU-specific memory and registers.",
                "Concrete CPU profile required",JOptionPane.WARNING_MESSAGE);
            return;
        }
        final List<HardwareApplyPlan.Item> candidates=
            new ArrayList<>(HardwareApplyPlan.mc68332Mm1Candidates(0,csbarEvidence()));
        final List<HardwareApplyService.Decision> decisions=new ArrayList<>();
        for(HardwareApplyPlan.Item item:candidates)
            decisions.add(HardwareApplyService.preflight(program,item,candidates));
        final DefaultTableModel model=new DefaultTableModel(
            new Object[]{"Apply","Status","Type","Definition",
                         "Address range","Evidence / preflight result",
                         "Existing symbol","Ghidra SourceType","Proposal origin"},0){
            @Override public Class<?> getColumnClass(int index){
                return index==0?Boolean.class:String.class;
            }
            @Override public boolean isCellEditable(int row,int col){
                return col==0 && decisions.get(row).allowed();
            }
        };
        for(int i=0;i<candidates.size();i++){
            HardwareApplyPlan.Item item=candidates.get(i);
            HardwareApplyService.Decision d=decisions.get(i);
            model.addRow(new Object[]{
                d.selectedByDefault,d.state.name(),item.kind.name(),
                item.name,item.location(),d.description+" — "+item.details,
                provenanceRow(program,item,d,d.selectedByDefault).displayExistingName(),
                provenanceRow(program,item,d,d.selectedByDefault).sourceDescription(),
                "GhidrAssist review proposal"
            });
        }

        JTable table=new JTable(model);
        table.setRowHeight(Math.max(25,table.getFont().getSize()+9));
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        int[] widths={65,135,100,260,180,640,185,310,230};
        for(int i=0;i<widths.length;i++)
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        JScrollPane scroll=new JScrollPane(table);
        JLabel introduction=new JLabel("<html><b>MC68332 / MM=1 — review before editing Ghidra</b>"+
            "<br>Applicable internal module/register definitions are preselected. "+
            "Already defined or conflicting items are not. "+
            "Unverified VBR and external chip selects require manual selection. "+
            "Reserved module bytes remain undefined.<br>Ghidra SourceType is NOT proof of a human, script or AI author. "+
            "Export the review snapshot before Apply if an audit is needed."+
            "<br>CSBAR source gate: "+
            (latestCsbarReview==null?"UNKNOWN — rerun Analyze":
                latestCsbarReview.summary())+"</html>");
        introduction.setBorder(BorderFactory.createEmptyBorder(8,10,8,10));

        JTextField vbrField=new JTextField("000000",9);
        JLabel vbrNotice=new JLabel("VBR is optional; runtime base must be verified.");
        final int vbrIndex=candidates.size()-1;
        Runnable updateVbr=()->{
            String digits=vbrField.getText().trim().replaceFirst("(?i)^0x","");
            try{
                long value=Long.parseUnsignedLong(digits,16);
                List<HardwareApplyPlan.Item> updated=
                    HardwareApplyPlan.mc68332Mm1Candidates(value,csbarEvidence());
                HardwareApplyPlan.Item item=updated.get(vbrIndex);
                candidates.set(vbrIndex,item);
                HardwareApplyService.Decision d=
                    HardwareApplyService.preflight(program,item,candidates);
                decisions.set(vbrIndex,d);
                model.setValueAt(d.state.name(),vbrIndex,1);
                model.setValueAt(item.location(),vbrIndex,4);
                model.setValueAt(d.description+" — "+item.details,vbrIndex,5);
                var prov=provenanceRow(program,item,d,
                    Boolean.TRUE.equals(model.getValueAt(vbrIndex,0)));
                model.setValueAt(prov.displayExistingName(),vbrIndex,6);
                model.setValueAt(prov.sourceDescription(),vbrIndex,7);
                if(!d.allowed())model.setValueAt(false,vbrIndex,0);
                vbrNotice.setText("VBR: "+d.description);
            }catch(Exception ex){
                model.setValueAt(false,vbrIndex,0);
                vbrNotice.setText("Invalid VBR base — hexadecimal and 4-byte aligned");
            }
        };
        vbrField.getDocument().addDocumentListener(new DocumentListener(){
            public void insertUpdate(DocumentEvent e){updateVbr.run();}
            public void removeUpdate(DocumentEvent e){updateVbr.run();}
            public void changedUpdate(DocumentEvent e){updateVbr.run();}
        });

        JPanel vbrPanel=new JPanel(new FlowLayout(FlowLayout.LEFT,8,3));
        vbrPanel.add(new JLabel("Optional VBR base (hex):"));
        vbrPanel.add(vbrField);
        vbrPanel.add(vbrNotice);

        JButton selectSafe=new JButton("Select applicable");
        JButton exportProvenance=new JButton("Export review CSV...");
        JButton deselect=new JButton("Clear selection");
        JButton apply=new JButton("Apply selected...");
        JButton cancel=new JButton("Cancel");
        JLabel countLabel=new JLabel();
        Runnable updateCount=()->{
            int selected=0,blocked=0,existing=0;
            for(int i=0;i<model.getRowCount();i++){
                if(Boolean.TRUE.equals(model.getValueAt(i,0)))selected++;
                if(decisions.get(i).state==HardwareApplyService.State.BLOCKED)blocked++;
                if(decisions.get(i).state==HardwareApplyService.State.ALREADY_PRESENT)existing++;
            }
            countLabel.setText(selected+" selected, "+existing+
                " existing, "+blocked+" blocked");
        };
        // Keep dependent register checkboxes consistent with the selected module block.
        // A mapped register remains independent when its parent region already exists.
        final boolean[] syncing=new boolean[1];
        model.addTableModelListener(e->{
            if(!syncing[0] && e.getColumn()==0){
                syncing[0]=true;
                try{
                    for(int k=0;k<candidates.size();k++){
                        HardwareApplyPlan.Item child=candidates.get(k);
                        if(child.kind!=HardwareApplyPlan.Kind.REGISTER)continue;
                        if(!Boolean.TRUE.equals(model.getValueAt(k,0)))continue;
                        boolean mapped=program.getMemory().contains(
                            program.getAddressFactory().getDefaultAddressSpace().getAddress(child.address));
                        if(mapped)continue;
                        boolean parentSelected=false;
                        for(int j=0;j<candidates.size();j++){
                            HardwareApplyPlan.Item parent=candidates.get(j);
                            if(parent.kind==HardwareApplyPlan.Kind.MEMORY &&
                                parent.address<=child.address && parent.last()>=child.last() &&
                                Boolean.TRUE.equals(model.getValueAt(j,0))){
                                parentSelected=true;
                                break;
                            }
                        }
                        if(!parentSelected)model.setValueAt(false,k,0);
                    }
                }finally{syncing[0]=false;}
            }
            updateCount.run();
        });
        updateCount.run();
        selectSafe.addActionListener(e->{
            for(int i=0;i<candidates.size();i++){
                HardwareApplyService.State state=decisions.get(i).state;
                model.setValueAt(state==HardwareApplyService.State.READY||
                    state==HardwareApplyService.State.UPGRADE,i,0);
            }
        });
        deselect.addActionListener(e->{
            for(int i=0;i<candidates.size();i++)model.setValueAt(false,i,0);
        });

        JPanel row=new JPanel(new FlowLayout(FlowLayout.LEFT,7,5));
        row.add(selectSafe);row.add(deselect);row.add(exportProvenance);row.add(countLabel);
        row.add(apply);row.add(cancel);
        JPanel footer=new JPanel(new BorderLayout());
        footer.add(vbrPanel,BorderLayout.NORTH);
        footer.add(row,BorderLayout.SOUTH);
        JPanel content=new JPanel(new BorderLayout(5,5));
        content.add(introduction,BorderLayout.NORTH);
        content.add(scroll,BorderLayout.CENTER);
        content.add(footer,BorderLayout.SOUTH);
        content.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));

        Window owner=SwingUtilities.getWindowAncestor(this);
        JDialog dialog=new JDialog(owner,
            "Review / Apply hardware definitions",Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        dialog.setContentPane(content);
        Dimension screen=Toolkit.getDefaultToolkit().getScreenSize();
        java.util.prefs.Preferences windowPreferences =
            java.util.prefs.Preferences.userNodeForPackage(HardwareAnalysisTab.class);
        int preferredWidth = windowPreferences.getInt("hardware.review.width", 1480);
        int preferredHeight = windowPreferences.getInt("hardware.review.height", 900);
        dialog.setSize(Math.min(screen.width-60,Math.max(900,preferredWidth)),
            Math.min(screen.height-90,Math.max(600,preferredHeight)));
        dialog.addWindowListener(new java.awt.event.WindowAdapter(){
            @Override public void windowClosed(java.awt.event.WindowEvent e){
                windowPreferences.putInt("hardware.review.width",dialog.getWidth());
                windowPreferences.putInt("hardware.review.height",dialog.getHeight());
            }
        });
        dialog.setMinimumSize(new Dimension(690,420));
        dialog.setResizable(true);
        dialog.setLocationRelativeTo(this);

        final List<HardwareApplyPlan.Item> accepted=new ArrayList<>();
        cancel.addActionListener(e->dialog.dispose());
        exportProvenance.addActionListener(e->{
            // The dialog may have been open while Ghidra symbols, memory
            // or profile changed: identity alone does not guard the receipt.
            if(!currentScan()){
                JOptionPane.showMessageDialog(dialog,
                    "The active program changed; rerun Analyze before exporting.",
                    "Stale review",JOptionPane.WARNING_MESSAGE);
                return;
            }
            if(table.isEditing() && !table.getCellEditor().stopCellEditing())return;
            List<HardwareChangeProvenance.ReviewRow> snapshot=new ArrayList<>();
            for(int i=0;i<candidates.size();i++)
                snapshot.add(provenanceRow(program,candidates.get(i),decisions.get(i),
                    Boolean.TRUE.equals(model.getValueAt(i,0))));
            String csv=HardwareChangeProvenance.csv(
                HardwareChangeProvenance.snapshot(snapshot));
            if(!currentScan()){
                status.setText("Review changed during provenance collection; nothing exported.");
                return;
            }
            JFileChooser chooser=new JFileChooser();
            chooser.setDialogTitle("Export local review provenance CSV");
            chooser.setSelectedFile(new File("ghidrassist-hardware-review-provenance.csv"));
            if(chooser.showSaveDialog(dialog)!=JFileChooser.APPROVE_OPTION)return;
            File destination=chooser.getSelectedFile();
            if(destination.exists() && JOptionPane.showConfirmDialog(dialog,
                    "Overwrite existing file: "+destination.getName()+"?",
                    "Confirm CSV overwrite",JOptionPane.YES_NO_OPTION)!=
                    JOptionPane.YES_OPTION)return;
            // JFileChooser and overwrite confirmation run nested Swing event
            // loops. Re-check the *full* version token after both dialogs.
            if(!currentScan()){
                status.setText("Stale Review revision: provenance CSV not written.");
                return;
            }
            try{
                Files.writeString(destination.toPath(),csv,StandardCharsets.UTF_8);
                JOptionPane.showMessageDialog(dialog,
                    snapshot.size()+" proposal rows exported locally.\n"+
                    "SourceType does not identify the human/script/AI author.",
                    "Review provenance exported",JOptionPane.INFORMATION_MESSAGE);
            }catch(Exception problem){
                JOptionPane.showMessageDialog(dialog,
                    "Could not export review CSV: "+problem.getMessage(),
                    "Export error",JOptionPane.ERROR_MESSAGE);
            }
        });
        apply.addActionListener(e->{
            if(table.isEditing())table.getCellEditor().stopCellEditing();
            accepted.clear();
            for(int i=0;i<candidates.size();i++){
                if(!Boolean.TRUE.equals(model.getValueAt(i,0)))continue;
                HardwareApplyService.Decision d=decisions.get(i);
                if(!d.allowed()){
                    JOptionPane.showMessageDialog(dialog,
                        "Blocked item: "+candidates.get(i).name+
                        "\n"+d.description,
                        "Cannot select conflict",JOptionPane.WARNING_MESSAGE);
                    return;
                }
                if(i==vbrIndex){
                    try {
                        String digits=vbrField.getText().trim().replaceFirst("(?i)^0x","");
                        candidates.set(i,HardwareApplyPlan.mc68332Mm1Candidates(
                            Long.parseUnsignedLong(digits,16)).get(i));
                    }catch(Exception exception){
                        JOptionPane.showMessageDialog(dialog,
                            "VBR base is invalid; correct or deselect its row.",
                            "Invalid VBR",JOptionPane.WARNING_MESSAGE);
                        return;
                    }
                }
                accepted.add(candidates.get(i));
            }
            if(accepted.isEmpty()){
                JOptionPane.showMessageDialog(dialog,
                    "Nothing is selected; the Ghidra project will remain unchanged.",
                    "No definitions to apply",JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            dialog.dispose();
        });
        dialog.setVisible(true);
        if(accepted.isEmpty())return;
        if(!currentScan()){
            status.setText("Program revision changed; no definitions applied.");
            return;
        }
        int confirm=JOptionPane.showConfirmDialog(this,
            "Apply "+accepted.size()+" approved definition(s) in ONE undoable"+
            " Ghidra transaction?\n"+
            "This modifies only the current Ghidra project, not firmware on disk.\n"+
            "The selected MC68332 profile is a USER ASSUMPTION.\n"+
            "Existing code, typed data and user-defined symbols will not be erased.",
            "Final confirmation: modify Ghidra database",
            JOptionPane.YES_NO_OPTION,JOptionPane.WARNING_MESSAGE);
        if(confirm!=JOptionPane.YES_OPTION)return;
        // A Ghidra edit/Undo/Redo can occur while the modal confirmation
        // is visible: revalidate identity, profile and modification counter
        // *after* consent, immediately before beginning the transaction.
        if(!currentScan()){
            status.setText("Program/profile revision changed during confirmation; Apply blocked.");
            return;
        }
        try{
            HardwareApplyService.Outcome outcome=
                HardwareApplyService.apply(program,accepted);
            StringBuilder details=new StringBuilder();
            long named=outcome.messages.stream()
                .filter(line->line.startsWith("DEFINED REGISTER ")).count();
            long mapped=outcome.messages.stream()
                .filter(line->line.startsWith("NEW CS REGION ") ||
                    line.startsWith("NEW MODULE REGION ") ||
                    line.startsWith("UPGRADED MODULE REGION ")).count();
            details.append("Operation origin: explicitly approved via GhidrAssist Review / Apply.\n")
                .append("Ghidra USER_DEFINED SourceType does not identify a human or AI author.\n")
                .append("Use the optional review CSV for a local pre-Apply snapshot.\n\n");
            details.append("Changed: ").append(outcome.changed)
                .append("; skipped: ").append(outcome.skipped)
                .append("; register names: ").append(named)
                .append("; memory regions/fragments: ").append(mapped)
                .append("\n\n");
            for(String line:outcome.messages)details.append(line).append("\n");
            JTextArea result=new JTextArea(details.toString(),18,95);
            result.setEditable(false);
            JOptionPane.showMessageDialog(this,new JScrollPane(result),
                "Review / Apply result — Ghidra Undo is available",
                JOptionPane.INFORMATION_MESSAGE);
            status.setText(outcome.changed+" changed, "+outcome.skipped+
                " skipped. Rerun Analyze to refresh evidence.");
            ghidrassist.hardware.HardwareEvidenceCache.clear(program);
            latestMarkdown=null;latestConfigCsv=null;latestNameCsv=null;
            latestRevision=null;
            approve.setEnabled(false);export.setEnabled(false);exportConfigCsv.setEnabled(false);
            namePreview.setEnabled(false);
            reviewNames.setEnabled(false);
            exploreMmio.setEnabled(false);
            latestFunctionProposals=List.of();
        }catch(Exception ex){
            ghidra.util.Msg.error(this,
                "Hardware Apply failed; transaction rolled back",ex);
            JOptionPane.showMessageDialog(this,
                "Transaction rolled back — no changes committed.\n"+
                ex.getClass().getSimpleName()+": "+ex.getMessage(),
                "Apply error",JOptionPane.ERROR_MESSAGE);
        }
    }

}
