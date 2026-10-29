package ghidrassist.hardware;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

public final class HardwareProfilePdfHashCheckSelfTest {
    private HardwareProfilePdfHashCheckSelfTest(){}
    private static void check(boolean yes,String why){
        if(!yes)throw new AssertionError(why);
    }
    private static String digest(byte[] data)throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
    }
    public static void main(String[] args)throws Exception {
        byte[] input="%PDF-1.4\nsynthetic-test-only".getBytes(StandardCharsets.US_ASCII);
        String expected=digest(input);
        var ok=HardwareProfilePdfHashCheck.verify(
            new ByteArrayInputStream(input),expected,1024);
        check(ok.status()==HardwareProfilePdfHashCheck.Status.MATCH &&
            ok.computedSha256().equals(expected) && ok.bytes()==input.length,
            "actual bytes match declared hash");
        check(ok.report().contains("NOT validate the manual edition") &&
            ok.report().contains("No document imported"),
            "matching hash cannot promote source semantics");
        var mismatch=HardwareProfilePdfHashCheck.verify(
            new ByteArrayInputStream(input),"0".repeat(64),1024);
        check(mismatch.status()==HardwareProfilePdfHashCheck.Status.MISMATCH,
            "wrong claimed hash must never pass");
        var unknown=HardwareProfilePdfHashCheck.verify(
            new ByteArrayInputStream(input),"UNKNOWN",1024);
        check(unknown.status()==HardwareProfilePdfHashCheck.Status.CLAIM_UNKNOWN &&
            unknown.computedSha256()==null,"unknown digest cannot be guessed");
        var bad=HardwareProfilePdfHashCheck.verify(
            new ByteArrayInputStream("not-a-pdf".getBytes(StandardCharsets.UTF_8)),
            digest("not-a-pdf".getBytes(StandardCharsets.UTF_8)),100);
        check(bad.status()==HardwareProfilePdfHashCheck.Status.INVALID_PDF,
            "non-PDF must not be trusted solely because the hash matches");
        var cap=HardwareProfilePdfHashCheck.verify(
            new ByteArrayInputStream(input),expected,5);
        check(cap.status()==HardwareProfilePdfHashCheck.Status.TOO_LARGE,
            "bounded streaming must reject oversize file");
        boolean invalid=false;
        try{HardwareProfilePdfHashCheck.verify(
            new ByteArrayInputStream(input),"x".repeat(64),100);}
        catch(IllegalArgumentException ex){invalid=true;}
        check(invalid,"malformed digest rejected");
        invalid=false;
        try{HardwareProfilePdfHashCheck.verify(null,expected,100);}
        catch(IllegalArgumentException ex){invalid=true;}
        check(invalid,"null stream rejected");
        System.out.println("HardwareProfilePdfHashCheckSelfTest OK");
    }
}
