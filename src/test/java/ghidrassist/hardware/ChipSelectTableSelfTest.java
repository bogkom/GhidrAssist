package ghidrassist.hardware;

import java.util.Map;

public final class ChipSelectTableSelfTest {
    private static void check(boolean ok, String reason) {
        if (!ok) throw new AssertionError(reason);
    }
    public static void main(String[] args) {
        String empty = ChipSelectTable.markdown(Map.of(), true);
        for (int i = -1; i <= 10; i++) {
            String label = i < 0 ? "CSBOOT" : "CS" + i;
            check(empty.contains("| " + label + " | UNKNOWN | UNKNOWN | UNKNOWN |"),
                "missing independent select: " + label);
        }
        check(empty.lines().filter(x -> x.matches("\\| CS(?:BOOT|[0-9]+) \\|.*")).count() == 12,
            "exactly 12 independent selects");
        String known = ChipSelectTable.markdown(
            Map.of("CSBARBT", 0x0006, "CSORBT", 0x6830,
                   "CSBAR0", 0xf803, "CSOR0", 0x3870, "CSPAR0", 0x2f7f), true);
        check(known.contains("| CSBOOT | 0x000000 | 0x07FFFF | 512 KiB |"),
            "CSBOOT based on decoded CSBAR");
        check(known.contains("| CS0 | 0xF80000 | 0xF8FFFF | 64 KiB |"),
            "CS0 based on decoded CSBAR");
        check(known.contains("CS1 | UNKNOWN"), "unseen CS remains unknown");
        check(known.contains("CONDITIONAL"), "not a proven map");
        String generic = ChipSelectTable.markdown(Map.of("CSBAR0", 0xf803), false);
        check(!generic.contains("| CS0 |"), "generic CPU32 cannot inherit MC68332");
        // A missing literal is explicit UNKNOWN, not a reason to drop
        // any of the twelve independent MC68332 rows.
        String partial=ChipSelectTable.markdown(
            Map.of("CSBAR0",0xf803),true);
        check(partial.contains("| CS0 | 0xF80000 | 0xF8FFFF | 64 KiB |")
                && partial.contains("PARTIAL: CSOR/CSPAR unknown"),
            "CSBAR-only evidence retains a conditional, partial CS row");
        check(partial.lines().filter(x -> x.matches(
            "\\| CS(?:BOOT|[0-9]+) \\|.*")).count()==12,
            "partial evidence still produces precisely twelve rows");
        String disabled=ChipSelectTable.markdown(
            Map.of("CSBAR0",0xf803,"CSOR0",0x3870,"CSPAR0",0),true);
        check(disabled.contains("NOT ELIGIBLE under observed values"),
            "pin-mode evidence must not claim a possible bus assertion");
        String unknownWord=ChipSelectTable.markdown(
            Map.of("CSOR0",0x3870,"CSPAR0",0x2f7f),true);
        check(unknownWord.contains("| CS0 | UNKNOWN | UNKNOWN | UNKNOWN |")
                && unknownWord.contains("UNKNOWN: missing CSBAR"),
            "CSOR and CSPAR alone never synthesize an address window");
        for(Map<String,Integer> invalidWords:java.util.List.of(
                Map.of("CSBAR0",-1),
                Map.of("CSOR0",0x10000),
                Map.of("CSPAR0",-2))) {
            boolean rejected=false;
            try {ChipSelectTable.markdown(invalidWords,true);}
            catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"out-of-range register word must fail closed");
        }
        boolean noSourceRejected=false;
        try {ChipSelectTable.markdown(null,true);}
        catch(IllegalArgumentException expected){noSourceRejected=true;}
        check(noSourceRejected,"missing source word map rejected");
        // Two conflicting function-local BAR writes invalidate the
        // exact range even if CSOR and CSPAR have consistent literals.
        var conflict=HardwareStaticWordConsensus.inspect(java.util.List.of(
            new HardwareStaticWordConsensus.Observation(
                "CSBAR0",true,0xf803),
            new HardwareStaticWordConsensus.Observation(
                "CSBAR0",true,0xe803),
            new HardwareStaticWordConsensus.Observation(
                "CSOR0",true,0x3870),
            new HardwareStaticWordConsensus.Observation(
                "CSPAR0",true,0x2f7f)));
        String disputed=ChipSelectTable.markdown(
            conflict.singleLiteralCandidates(),true);
        check(conflict.conflictedRegisters()==1 &&
                disputed.contains("| CS0 | UNKNOWN | UNKNOWN | UNKNOWN |") &&
                disputed.contains("UNKNOWN: missing CSBAR") &&
                !disputed.contains("| CS0 | 0xF80000"),
            "conflicting CSBAR literals must not create a false map");
        var noLiteral=HardwareStaticWordConsensus.inspect(java.util.List.of(
            new HardwareStaticWordConsensus.Observation(
                "CSBAR0",true,null),
            new HardwareStaticWordConsensus.Observation(
                "CSPAR0",true,0x2f7f)));
        check(ChipSelectTable.markdown(
                noLiteral.singleLiteralCandidates(),true)
                .contains("| CS0 | UNKNOWN | UNKNOWN | UNKNOWN |"),
            "unknown source write preserves UNKNOWN select window");
        System.out.println("ChipSelectTableSelfTest OK");
    }
}
