package ghidrassist.ui.common;

import java.awt.event.InputEvent;
import java.awt.event.MouseEvent;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.event.PopupMenuEvent;

/** Headless-safe test of chat composer mouse editing behavior. */
public final class MousePasteSupportSelfTest {
    private static void check(boolean valid,String failure) {
        if(!valid)throw new AssertionError(failure);
    }
    private static class FakeInput extends JTextArea {
        @Override public void paste() { replaceSelection("CLIPBOARD"); }
    }
    public static void main(String[] args) throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            FakeInput composer=new FakeInput();
            composer.setText("HINT");
            MousePasteSupport.install(composer,()->{
                if(composer.getText().equals("HINT"))composer.setText("");
            });
            JPopupMenu menu=composer.getComponentPopupMenu();
            check(menu!=null,"composer context menu");
            JMenuItem paste=(JMenuItem)menu.getComponent(2);
            check(paste.getText().equals("Paste"),"visible Paste command");
            menu.getPopupMenuListeners()[0].popupMenuWillBecomeVisible(
                new PopupMenuEvent(menu));
            check(paste.isEnabled(),"paste enabled in composer");
            paste.doClick();
            check(composer.getText().equals("CLIPBOARD"),"paste replaces placeholder");
            composer.select(0,composer.getText().length());
            JMenuItem cut=(JMenuItem)menu.getComponent(0);
            menu.getPopupMenuListeners()[0].popupMenuWillBecomeVisible(
                new PopupMenuEvent(menu));
            check(cut.isEnabled(),"cut selected composer text");
            cut.doClick();
            check(composer.getText().isEmpty(),"cut removes selection");
            composer.setEditable(false);
            menu.getPopupMenuListeners()[0].popupMenuWillBecomeVisible(
                new PopupMenuEvent(menu));
            check(!paste.isEnabled(),"read-only composer cannot paste");
            composer.setEditable(true);
            composer.setText("");
            composer.setSize(400,80);
            MouseEvent middle=new MouseEvent(composer,MouseEvent.MOUSE_PRESSED,
                System.currentTimeMillis(),InputEvent.BUTTON2_DOWN_MASK,5,5,
                1,false,MouseEvent.BUTTON2);
            composer.dispatchEvent(middle);
            check(composer.getText().equals("CLIPBOARD"),
                "middle mouse paste falls back to clipboard if PRIMARY absent");
        });
        System.out.println("MousePasteSupportSelfTest OK");
    }
}
