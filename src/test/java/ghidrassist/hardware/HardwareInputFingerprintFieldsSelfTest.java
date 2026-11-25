package ghidrassist.hardware;

import java.security.MessageDigest;
import java.util.HexFormat;

/** GA-12: deterministic, Ghidra-free field and function-body identity tests. */
public final class HardwareInputFingerprintFieldsSelfTest {
    private static int assertions;
    private HardwareInputFingerprintFieldsSelfTest(){}
    private static void ok(boolean condition,String message){
        assertions++;
        if(!condition)throw new AssertionError(message);
    }
    private static MessageDigest sha(){
        try{return MessageDigest.getInstance("SHA-256");}
        catch(java.security.NoSuchAlgorithmException e){throw new AssertionError(e);}
    }
    private static String hex(MessageDigest digest){
        return HexFormat.of().formatHex(digest.digest());
    }
    private static String one(String value){
        MessageDigest digest=sha();
        HardwareInputFingerprintFields.string(digest,value);
        return hex(digest);
    }
    private static String body(String[][] ranges){
        MessageDigest digest=sha();
        for(String[] range:ranges)
            HardwareInputFingerprintFields.functionRange(
                digest,range[0],range[1]);
        HardwareInputFingerprintFields.endFunctionRanges(digest,ranges.length);
        return hex(digest);
    }
    private static void rejects(Runnable operation,String message){
        boolean rejected=false;
        try{operation.run();}
        catch(IllegalArgumentException expected){rejected=true;}
        ok(rejected,message);
    }
    public static void main(String[] args){
        ok(!one(null).equals(one("<null>")),
            "absent field must not collide with literal former null sentinel");
        ok(!one(null).equals(one("")) &&
            !one("").equals(one("<null>")),
            "missing, empty and textual sentinel are distinct inputs");
        ok(!one("ą").equals(one("a")) &&
            !one("ą").equals(one("??")),
            "source encoding includes exact UTF-8 bytes");
        ok(one("same").equals(one("same")),
            "identical field encoding is deterministic across digests");

        String[][] contiguous={{"0x00000100","0x00000107"}};
        String[][] split={{"0x00000100","0x00000103"},
                          {"0x00000108","0x0000010B"}};
        ok(!body(contiguous).equals(body(split)),
            "same-size contiguous and disjoint function bodies cannot share CFG key");
        ok(body(split).equals(body(split)),
            "unchanged function geometry is stable");
        ok(!body(new String[0][0]).equals(body(contiguous)) &&
            !body(new String[0][0]).equals(body(split)),
            "empty versus populated range inventory differs");
        ok(!body(new String[][]{{"0x100","0x103"}}).equals(
                body(new String[][]{{"0x100","0x104"}})),
            "changed range upper bound invalidates cached CFG");
        ok(!body(split).equals(body(new String[][]{
                {"0x00000108","0x0000010B"},
                {"0x00000100","0x00000103"}})),
            "range ordering is explicitly part of source identity");

        rejects(()->HardwareInputFingerprintFields.string(null,"text"),
            "digest cannot be null");
        rejects(()->HardwareInputFingerprintFields.functionRange(
                sha(),null,"0x104"),
            "missing function range start is refused");
        rejects(()->HardwareInputFingerprintFields.functionRange(
                sha(),"0x100",null),
            "missing function range end is refused");
        rejects(()->HardwareInputFingerprintFields.endFunctionRanges(sha(),-1),
            "negative range count refused");
        rejects(()->HardwareInputFingerprintFields.endFunctionRanges(
                sha(),1_000_001),
            "unbounded function range list refused");
        System.out.println("HardwareInputFingerprintFieldsSelfTest PASS: assertions="+assertions);
    }
}
