package ghidrassist.ui.common;

import java.util.Arrays;
import javax.swing.JPasswordField;
import javax.swing.SwingUtilities;

/** Headless Swing regression: credentials stay masked by default. */
public final class ProviderSecretFieldSelfTest {
    private static void check(boolean value, String description) {
        if (!value) throw new AssertionError(description);
    }

    public static void main(String[] args) throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            String fakeSecret = "{\"access_token\":\"FAKE_TEST_VALUE\"}";
            JPasswordField secret = new JPasswordField(fakeSecret, 28);
            ProviderSecretField control = new ProviderSecretField(secret);
            check(secret.echoCharIsSet() && secret.getEchoChar() == '*', "Credential must be masked initially");
            check("Show".equals(control.getRevealButton().getText()), "Initial action is Show");
            control.getRevealButton().doClick();
            check(!secret.echoCharIsSet(), "Reveal must be explicit");
            check("Hide".equals(control.getRevealButton().getText()), "Revealed action is Hide");
            control.getRevealButton().doClick();
            check(secret.echoCharIsSet() && secret.getEchoChar() == '*', "Hide restores masking");
            char[] password = secret.getPassword();
            try { check(fakeSecret.equals(new String(password)), "Toggle must not modify credential data"); }
            finally { Arrays.fill(password, '\0'); }
            secret.setText("REFRESHED_FAKE_TOKEN");
            check(secret.echoCharIsSet(), "Authentication refresh must not unmask the field");
            ProviderSecretField nextDialog = new ProviderSecretField(new JPasswordField(fakeSecret, 28));
            check(nextDialog.getPasswordField().echoCharIsSet(), "Each dialog starts masked");
            System.out.println("ProviderSecretFieldSelfTest: PASS");
        });
    }
}
