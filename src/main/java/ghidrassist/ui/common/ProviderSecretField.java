package ghidrassist.ui.common;

import java.awt.BorderLayout;
import java.util.Objects;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

/** Masked credential editor with explicit per-dialog reveal control. */
public final class ProviderSecretField extends JPanel {
    private static final long serialVersionUID = 1L;
    private final JPasswordField passwordField;
    private final JButton revealButton;

    public ProviderSecretField(JPasswordField passwordField) {
        super(new BorderLayout(6, 0));
        this.passwordField = Objects.requireNonNull(passwordField, "passwordField");
        this.passwordField.setEchoChar('*');
        revealButton = new JButton("Show");
        revealButton.setToolTipText("Temporarily show or hide the credentials");
        revealButton.addActionListener(event -> setRevealed(passwordField.echoCharIsSet()));
        add(this.passwordField, BorderLayout.CENTER);
        add(revealButton, BorderLayout.EAST);
    }

    public void setRevealed(boolean revealed) {
        passwordField.setEchoChar(revealed ? (char) 0 : '*');
        revealButton.setText(revealed ? "Hide" : "Show");
    }

    public JPasswordField getPasswordField() {
        return passwordField;
    }

    public JButton getRevealButton() {
        return revealButton;
    }
}
