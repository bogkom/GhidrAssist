package ghidrassist.hardware;

public final class McpEvidenceGuardSelfTest {
    private static void ok(boolean yes,String why){if(!yes)throw new AssertionError(why);}
    public static void main(String[] args){
        String code="0006ea28: move.w #-0x7fd, (0x00fffa4c).l\n"+
            "0006ea30: move.w #0x3870, (0x00fffa4e).l\n"+
            "0006ea38: move.w #-0x7fd, (0x00fffa50).l\n"+
            "0006ea40: move.w #0x5870, (0x00fffa52).l\n";
        String found=McpEvidenceGuard.enrich("ghidrassistmcp_get_disassembly",code);
        ok(found.contains("0xF803")&&found.contains("0x0006EA28"),"signed immediate and pc");
        ok(found.contains("CSBAR0")&&found.contains("CSOR1"),"conditional mapping labels");
        ok(found.contains("0x6000")&&found.contains("[13, 14]"),"XOR and bits");
        ok(McpEvidenceGuard.xor16(0x3870,0x3830)==0x0040,"xor16");
        ok(McpEvidenceGuard.setBits(0x0040).equals("[6]"),"bit 6");
        ok(McpEvidenceGuard.enrich("get_disassembly",code.replace("\n","\\n")).contains("0x6000"),
           "SDK escaped newlines");
        ok(McpEvidenceGuard.enrich("get_function_info",code).equals(code),"no other tools changed");
        ok(McpEvidenceGuard.enrich("get_disassembly","unrelated").equals("unrelated"),
           "no invented evidence");
        System.out.println("McpEvidenceGuardSelfTest OK");
    }
}
