package ghidrassist.ui.common;

import java.awt.HeadlessException;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import javax.swing.JComponent;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.SwingUtilities;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.text.JTextComponent;

/** Mouse-driven editing in Swing text inputs, including Linux PRIMARY paste. */
public final class MousePasteSupport {
    private MousePasteSupport() {}

    public static void install(JTextComponent input, Runnable beforePaste) {
        JPopupMenu menu=new JPopupMenu();
        JMenuItem cut=new JMenuItem("Cut");
        JMenuItem copy=new JMenuItem("Copy");
        JMenuItem paste=new JMenuItem("Paste");
        JMenuItem all=new JMenuItem("Select All");
        cut.addActionListener(e -> input.cut());
        copy.addActionListener(e -> input.copy());
        paste.addActionListener(e -> pasteFromClipboard(input,beforePaste));
        all.addActionListener(e -> input.selectAll());
        menu.add(cut);
        menu.add(copy);
        menu.add(paste);
        menu.addSeparator();
        menu.add(all);
        menu.addPopupMenuListener(new PopupMenuListener() {
            @Override public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                boolean enabled=input.isEnabled();
                boolean editable=enabled && input.isEditable();
                boolean selected=input.getSelectionStart()!=input.getSelectionEnd();
                cut.setEnabled(editable && selected);
                copy.setEnabled(enabled && selected);
                paste.setEnabled(editable);
                all.setEnabled(enabled && input.getDocument().getLength()>0);
            }
            @Override public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {}
            @Override public void popupMenuCanceled(PopupMenuEvent e) {}
        });
        input.setComponentPopupMenu(menu);
        installMiddleClick(input,beforePaste);
    }

    /** Reuse on text inputs which already have a specialized context menu. */
    public static void installMiddleClick(JTextComponent input,Runnable beforePaste) {
        input.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) {
                if (!SwingUtilities.isMiddleMouseButton(e) ||
                        !input.isEditable() || !input.isEnabled())return;
                input.requestFocusInWindow();
                if(beforePaste!=null)beforePaste.run();
                int offset=input.viewToModel2D(e.getPoint());
                if(offset>=0)input.setCaretPosition(
                    Math.min(offset,input.getDocument().getLength()));
                String primary=readPrimarySelection();
                if(primary!=null)input.replaceSelection(primary);
                else input.paste(); // Wayland/Windows: use regular clipboard.
                e.consume();
            }
        });
    }

    public static void pasteFromClipboard(JTextComponent input,Runnable beforePaste) {
        if(!input.isEditable() || !input.isEnabled())return;
        input.requestFocusInWindow();
        if(beforePaste!=null)beforePaste.run();
        input.paste();
    }

    private static String readPrimarySelection() {
        try {
            Clipboard clipboard=Toolkit.getDefaultToolkit().getSystemSelection();
            if(clipboard==null)return null;
            Transferable t=clipboard.getContents(null);
            if(t==null || !t.isDataFlavorSupported(DataFlavor.stringFlavor))return null;
            return (String)t.getTransferData(DataFlavor.stringFlavor);
        }catch(HeadlessException | IllegalStateException |
                UnsupportedFlavorException | IOException | SecurityException ex){
            return null;
        }
    }
}
