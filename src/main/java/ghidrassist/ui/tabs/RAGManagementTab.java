package ghidrassist.ui.tabs;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import ghidrassist.core.RAGDocumentInfo;
import ghidrassist.core.RAGLibraries;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Set;
import ghidrassist.core.SearchResult;
import ghidrassist.core.TabController;

import java.util.List;

public class RAGManagementTab extends JPanel {
    private static final long serialVersionUID = 1L;
    private final TabController controller;

    // Document Management section
    private JTable documentTable;
    private DefaultTableModel documentTableModel;
    private JLabel statsLabel;
    private JButton addButton;
    private JButton downloadCpuManualsButton;
    private JButton refreshButton;
    private JButton deleteButton;
    private JButton clearIndexButton;
    private JButton moveDocumentButton;
    private JPanel libraryCheckboxPanel;
    private JComboBox<RAGLibraries.Library> libraryManagementCombo;
    private JButton addLibraryButton;
    private JButton renameLibraryButton;
    private JButton deleteLibraryButton;
    private boolean refreshingLibraries;

    // Search Documents section
    private JTextField queryField;
    private JComboBox<String> searchTypeCombo;
    private JButton searchButton;
    private JLabel resultsHeaderLabel;
    private JPanel resultsPanel;

    // Split pane
    private JSplitPane mainSplitPane;
    private JSplitPane libraryDocumentSplitPane;

    public RAGManagementTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        initializeComponents();
        layoutComponents();
        setupListeners();
    }

    private void initializeComponents() {
        // Document Management components
        addButton = new JButton("Add Documents");
        downloadCpuManualsButton = new JButton("Download CPU32 manuals...");
        downloadCpuManualsButton.setToolTipText(
            "Download source-verified NXP manuals to a local folder; RAG indexing remains manual");
        refreshButton = new JButton("Refresh");
        deleteButton = new JButton("Delete");
        clearIndexButton = new JButton("Clear Index");
        moveDocumentButton = new JButton("Move Document");
        libraryCheckboxPanel = new JPanel();
        libraryCheckboxPanel.setLayout(new GridLayout(0, 2, 8, 2));
        libraryManagementCombo = new JComboBox<>();
        addLibraryButton = new JButton("New");
        renameLibraryButton = new JButton("Rename");
        deleteLibraryButton = new JButton("Delete Library");
        statsLabel = new JLabel("Documents: 0 | Chunks: 0 | Embeddings: 0");

        // Document table
        documentTableModel = new DefaultTableModel(new Object[]{"Name", "Library", "Size", "Chunks"}, 0) {
            private static final long serialVersionUID = 1L;
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        documentTable = new JTable(documentTableModel);
        documentTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        documentTable.setAutoCreateRowSorter(true);
        documentTable.setRowHeight(20);
        documentTable.getColumnModel().getColumn(0).setPreferredWidth(200);
        documentTable.getColumnModel().getColumn(1).setPreferredWidth(120);
        documentTable.getColumnModel().getColumn(2).setPreferredWidth(80);
        documentTable.getColumnModel().getColumn(3).setPreferredWidth(60);

        // Search components
        queryField = new JTextField(20);
        queryField.setToolTipText("Put text in double quotes to find an exact phrase");
        searchTypeCombo = new JComboBox<>(new String[]{"Hybrid", "Semantic", "Keyword"});
        searchButton = new JButton("Search");
        resultsHeaderLabel = new JLabel(" ");
        resultsPanel = new JPanel();
        resultsPanel.setLayout(new BoxLayout(resultsPanel, BoxLayout.Y_AXIS));
    }

    private void layoutComponents() {
        // === TOP SECTION: Document Management ===
        JPanel documentManagementPanel = new JPanel(new BorderLayout());

        // Section header
        JLabel docHeader = new JLabel("Document Management");
        docHeader.setFont(docHeader.getFont().deriveFont(Font.BOLD));
        docHeader.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Toolbar row: Add button + stats
        JPanel toolbarPanel = new JPanel(new BorderLayout());
        toolbarPanel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
        JPanel documentActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        documentActions.add(addButton);
        documentActions.add(downloadCpuManualsButton);
        toolbarPanel.add(documentActions, BorderLayout.WEST);
        toolbarPanel.add(statsLabel, BorderLayout.EAST);

        // Top section (header + toolbar)
        JPanel docTopPanel = new JPanel(new BorderLayout());
        docTopPanel.add(docHeader, BorderLayout.NORTH);
        docTopPanel.add(toolbarPanel, BorderLayout.CENTER);

        JPanel librarySection = new JPanel(new BorderLayout(4, 4));
        librarySection.setBorder(BorderFactory.createTitledBorder("Active libraries (check one or more)"));
        JScrollPane libScroll = new JScrollPane(libraryCheckboxPanel);
        libScroll.setPreferredSize(new Dimension(350, 130));
        libScroll.setMinimumSize(new Dimension(175, 54));
        librarySection.add(libScroll, BorderLayout.CENTER);
        JPanel libraryControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 1));
        libraryControls.add(libraryManagementCombo);
        libraryControls.add(addLibraryButton);
        libraryControls.add(renameLibraryButton);
        libraryControls.add(deleteLibraryButton);
        librarySection.add(libraryControls, BorderLayout.SOUTH);
        // The library panel is independently resizable below the toolbar.

        // Bottom buttons
        JPanel docButtonPanel = new JPanel(new BorderLayout());
        docButtonPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        JPanel leftButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        leftButtons.add(refreshButton);
        leftButtons.add(deleteButton);
        leftButtons.add(moveDocumentButton);
        JPanel rightButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        rightButtons.add(clearIndexButton);
        docButtonPanel.add(leftButtons, BorderLayout.WEST);
        docButtonPanel.add(rightButtons, BorderLayout.EAST);

        // Assemble document management panel
        documentManagementPanel.add(docTopPanel, BorderLayout.NORTH);
        libraryDocumentSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                librarySection, new JScrollPane(documentTable));
        libraryDocumentSplitPane.setResizeWeight(0.24);
        libraryDocumentSplitPane.setOneTouchExpandable(true);
        documentManagementPanel.add(libraryDocumentSplitPane, BorderLayout.CENTER);
        documentManagementPanel.add(docButtonPanel, BorderLayout.SOUTH);

        // === BOTTOM SECTION: Search Documents ===
        JPanel searchPanel = new JPanel(new BorderLayout());

        // Section header
        JLabel searchHeader = new JLabel("Search Documents");
        searchHeader.setFont(searchHeader.getFont().deriveFont(Font.BOLD));
        searchHeader.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Search controls row
        JPanel searchControlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        searchControlsPanel.add(new JLabel("Query:"));
        searchControlsPanel.add(queryField);
        searchControlsPanel.add(new JLabel("Type:"));
        searchControlsPanel.add(searchTypeCombo);
        searchControlsPanel.add(searchButton);

        // Top section (header + controls)
        JPanel searchTopPanel = new JPanel(new BorderLayout());
        searchTopPanel.add(searchHeader, BorderLayout.NORTH);
        searchTopPanel.add(searchControlsPanel, BorderLayout.SOUTH);

        // Results container
        resultsHeaderLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        resultsHeaderLabel.setFont(resultsHeaderLabel.getFont().deriveFont(Font.BOLD));

        JPanel resultsContainer = new JPanel(new BorderLayout());
        resultsContainer.add(resultsHeaderLabel, BorderLayout.NORTH);
        JScrollPane resultsScrollPane = new JScrollPane(resultsPanel);
        resultsScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        resultsContainer.add(resultsScrollPane, BorderLayout.CENTER);

        // Assemble search panel
        searchPanel.add(searchTopPanel, BorderLayout.NORTH);
        searchPanel.add(resultsContainer, BorderLayout.CENTER);

        // === MAIN SPLIT ===
        mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                documentManagementPanel, searchPanel);
        mainSplitPane.setResizeWeight(0.6);

        // Set divider location to 60% after component is shown
        addHierarchyListener(e -> {
            if ((e.getChangeFlags() & java.awt.event.HierarchyEvent.SHOWING_CHANGED) != 0 && isShowing()) {
                SwingUtilities.invokeLater(() -> {
                    mainSplitPane.setDividerLocation(0.6);
                });
            }
        });

        add(mainSplitPane, BorderLayout.CENTER);
    }

    private void setupListeners() {
        addButton.addActionListener(e -> controller.handleAddDocuments());
        downloadCpuManualsButton.addActionListener(e -> controller.handleDownloadCpu32Manuals());
        deleteButton.addActionListener(e -> {
            int selectedRow = documentTable.getSelectedRow();
            if (selectedRow >= 0) {
                String filename = (String) documentTableModel.getValueAt(documentTable.convertRowIndexToModel(selectedRow), 0);
                controller.handleDeleteDocument(filename);
            }
        });
        refreshButton.addActionListener(e -> controller.refreshRAGDocuments());
        clearIndexButton.addActionListener(e -> controller.handleClearIndex());
        moveDocumentButton.addActionListener(e -> controller.handleMoveRAGDocument(getSelectedDocument()));
        addLibraryButton.addActionListener(e -> controller.handleCreateRAGLibrary());
        renameLibraryButton.addActionListener(e -> controller.handleRenameRAGLibrary(getManagedLibraryId()));
        deleteLibraryButton.addActionListener(e -> controller.handleDeleteRAGLibrary(getManagedLibraryId()));
        searchButton.addActionListener(e -> {
            String query = queryField.getText().trim();
            String searchType = (String) searchTypeCombo.getSelectedItem();
            if (!query.isEmpty()) {
                controller.handleRAGSearch(query, searchType, this);
            }
        });

        // Allow Enter key to trigger search
        queryField.addActionListener(e -> searchButton.doClick());
    }

    /**
     * Update the document table with document info.
     */
    public void updateDocumentTable(List<RAGDocumentInfo> docs) {
        documentTableModel.setRowCount(0);
        for (RAGDocumentInfo doc : docs) {
            String library = RAGLibraries.UNIVERSAL;
            try {
                String stored = ghidrassist.core.RAGEngine.getDocumentLibrary(doc.getFilename());
                if (stored != null) library = stored;
            } catch (java.io.IOException ex) {
                library = "?";
            }
            documentTableModel.addRow(new Object[]{
                    doc.getFilename(),
                    RAGLibraries.nameOf(library),
                    doc.getFormattedSize(),
                    doc.getChunkCount()
            });
        }
    }

    public void updateLibraries(List<RAGLibraries.Library> libraries, Set<String> active) {
        refreshingLibraries = true;
        try {
            RAGLibraries.Library prior = (RAGLibraries.Library) libraryManagementCombo.getSelectedItem();
            String priorId = prior == null ? null : prior.id;
            libraryManagementCombo.removeAllItems();
            libraryCheckboxPanel.removeAll();
            for (RAGLibraries.Library lib : libraries) {
                libraryManagementCombo.addItem(lib);
                JCheckBox check = new JCheckBox(lib.name, active.contains(lib.id));
                check.addActionListener(e -> {
                    if (!refreshingLibraries) controller.handleRAGLibrarySelection(getCheckedLibraryIds());
                });
                check.putClientProperty("rag.library.id", lib.id);
                libraryCheckboxPanel.add(check);
                if (lib.id.equals(priorId)) libraryManagementCombo.setSelectedItem(lib);
            }
            libraryCheckboxPanel.revalidate();
            libraryCheckboxPanel.repaint();
        } finally {
            refreshingLibraries = false;
        }
    }

    private Set<String> getCheckedLibraryIds() {
        Set<String> selected = new LinkedHashSet<>();
        for (Component component : libraryCheckboxPanel.getComponents()) {
            if (component instanceof JCheckBox) {
                JCheckBox box = (JCheckBox) component;
                if (box.isSelected()) selected.add((String) box.getClientProperty("rag.library.id"));
            }
        }
        return selected;
    }

    public String getManagedLibraryId() {
        RAGLibraries.Library lib = (RAGLibraries.Library) libraryManagementCombo.getSelectedItem();
        return lib == null ? null : lib.id;
    }

    /** User explicitly selects the destination even if multiple libraries are checked. */
    public String chooseTargetLibrary(String caption) {
        List<RAGLibraries.Library> libraries = RAGLibraries.list();
        JComboBox<RAGLibraries.Library> choice = new JComboBox<>(libraries.toArray(new RAGLibraries.Library[0]));
        String managed = getManagedLibraryId();
        for (RAGLibraries.Library lib : libraries) if (lib.id.equals(managed)) choice.setSelectedItem(lib);
        int result = JOptionPane.showConfirmDialog(this, choice, caption,
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (result != JOptionPane.OK_OPTION) return null;
        RAGLibraries.Library selected = (RAGLibraries.Library) choice.getSelectedItem();
        return selected == null ? null : selected.id;
    }

    /**
     * Update the statistics label.
     */
    public void updateStats(int docCount, int chunkCount, int embeddingCount) {
        statsLabel.setText(String.format("Documents: %d | Chunks: %d | Embeddings: %d",
                docCount, chunkCount, embeddingCount));
    }

    /**
     * Display search results.
     */
    public void displaySearchResults(String query, List<SearchResult> results, String searchType) {
        resultsPanel.removeAll();

        if (results.isEmpty()) {
            resultsHeaderLabel.setText(String.format("Search Results for '%s' (0 found)", query));
            JLabel noResults = new JLabel("No results found.");
            noResults.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            resultsPanel.add(noResults);
        } else {
            resultsHeaderLabel.setText(String.format("Search Results for '%s' (%d found)", query, results.size()));

            for (int i = 0; i < results.size(); i++) {
                SearchResult result = results.get(i);
                JPanel resultPanel = createResultPanel(i + 1, result, searchType);
                resultsPanel.add(resultPanel);
            }
        }

        resultsPanel.revalidate();
        resultsPanel.repaint();
    }

    /**
     * Create a panel for a single search result.
     */
    private JPanel createResultPanel(int index, SearchResult result, String searchType) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Title: "1. filename.c"
        JLabel titleLabel = new JLabel(index + ". " + result.getFilename());
        titleLabel.setForeground(new Color(0, 102, 204)); // Blue color
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD));
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Show original source PDF page, not just Lucene chunk number.
        String meta = String.format("Score: %.0f%% | Type: %s | Chunk: %d",
                result.getScore() * 100, searchType.toLowerCase(), result.getChunkId());
        if (result.getPageNumber() > 0) meta += " | PDF page: " + result.getPageNumber();
        JLabel metaLabel = new JLabel(meta);
        metaLabel.setFont(metaLabel.getFont().deriveFont(Font.PLAIN, 10f));
        metaLabel.setForeground(Color.GRAY);
        metaLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Selectable, copyable text with preserved line breaks.
        JTextArea excerpt = new JTextArea(result.getSnippet() == null ? "" : result.getSnippet());
        excerpt.setEditable(false);
        excerpt.setLineWrap(true);
        excerpt.setWrapStyleWord(true);
        excerpt.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        excerpt.setRows(5);
        JScrollPane excerptScroll = new JScrollPane(excerpt);
        excerptScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        excerptScroll.setPreferredSize(new Dimension(560, 100));

        panel.add(titleLabel);
        panel.add(Box.createVerticalStrut(2));
        panel.add(metaLabel);
        if (result.isUncertainTable()) {
            JLabel caution = new JLabel("Possible table / columns: verify exact register and bit values in source PDF.");
            caution.setForeground(new Color(160, 90, 0));
            caution.setAlignmentX(Component.LEFT_ALIGNMENT);
            panel.add(caution);
        }
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        actions.setAlignmentX(Component.LEFT_ALIGNMENT);
        JButton inspect = new JButton("View full indexed page / Copy");
        inspect.addActionListener(e -> showIndexedPage(result));
        actions.add(inspect);
        if (result.getSourcePath() != null && !result.getSourcePath().isBlank()) {
            JButton openSource = new JButton(result.getPageNumber() > 0
                ? "Open source PDF - page " + result.getPageNumber() : "Open source document");
            openSource.addActionListener(e -> controller.handleOpenRAGSource(result));
            actions.add(openSource);
        }
        panel.add(actions);
        panel.add(excerptScroll);

        // Set max width
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 240));

        return panel;
    }

    private void showIndexedPage(SearchResult result) {
        try {
            String content = ghidrassist.core.RAGEngine.getIndexedChunkContent(
                result.getFilename(), result.getChunkId());
            JTextArea full = new JTextArea(content, 28, 95);
            full.setEditable(false);
            full.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            full.setCaretPosition(0);
            JOptionPane.showMessageDialog(this, new JScrollPane(full),
                result.getFilename() + " / PDF page " + result.getPageNumber(),
                JOptionPane.INFORMATION_MESSAGE);
        } catch (java.io.IOException ex) {
            JOptionPane.showMessageDialog(this, "Unable to read indexed page: " + ex.getMessage(),
                "RAG index error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Escape HTML special characters.
     */
    private String escapeHtml(String text) {
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    /**
     * Clear search results.
     */
    public void clearSearchResults() {
        resultsHeaderLabel.setText(" ");
        resultsPanel.removeAll();
        resultsPanel.revalidate();
        resultsPanel.repaint();
    }

    /**
     * Get the document table for external access.
     */
    public JTable getDocumentTable() {
        return documentTable;
    }

    /**
     * Get selected document filename.
     */
    public String getSelectedDocument() {
        int selectedRow = documentTable.getSelectedRow();
        if (selectedRow >= 0) {
            return (String) documentTableModel.getValueAt(documentTable.convertRowIndexToModel(selectedRow), 0);
        }
        return null;
    }
}
