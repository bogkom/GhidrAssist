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
        // Retaining exactly 80 valid in-scope sources is complete only
        // when no 81st matching source can be found.
        StringBuilder eighty=new StringBuilder();
        for(int i=0;i<80;i++)
            eighty.append(String.format(java.util.Locale.ROOT,
                "%08x: move.w #0x1234, (0x00fffa4e).l\\n",0x100+2*i));
        String exactly80=McpEvidenceGuard.enrich("get_disassembly",
            eighty.toString());
        ok(!exactly80.contains("INCOMPLETE_EVIDENCE") &&
            exactly80.contains("0x0000019E"),
            "exactly 80 valid sources are retained without false truncation");
        String over=McpEvidenceGuard.enrich("get_disassembly",
            eighty+"000001a0: move.w #0x5678, (0x00fffa4e).l\\n");
        ok(over.contains("INCOMPLETE_EVIDENCE") &&
            over.contains("at least one additional matching") &&
            !over.contains("- instruction 0x000001A0"),
            "81st in-scope write is omitted with explicit incomplete marker");
        String outside=McpEvidenceGuard.enrich("get_disassembly",
            eighty+"000001a0: move.w #0x5678, (0x00001000).l\\n");
        ok(!outside.contains("INCOMPLETE_EVIDENCE"),
            "unrelated out-of-window write does not consume SIM evidence cap");
        String malformed="00000100: move.w #0x10000000000000000, (0x00fffa4e).l\\n";
        String unsafe=McpEvidenceGuard.enrich("get_disassembly",malformed);
        ok(unsafe.contains("INCOMPLETE_EVIDENCE") &&
            unsafe.contains("unrepresentable numeric immediate") &&
            !unsafe.contains("- instruction 0x00000100"),
            "unrepresentable 17-digit literal fails closed without throwing");
        String mixed=McpEvidenceGuard.enrich("get_disassembly",
            malformed+"00000102: move.w #0x40ca, (0x00fffa00).l\\n");
        ok(mixed.contains("INCOMPLETE_EVIDENCE") &&
            mixed.contains("- instruction 0x00000102"),
            "malformed evidence does not discard later valid SIM source");
        System.out.println("McpEvidenceGuardSelfTest OK");
    }
}
