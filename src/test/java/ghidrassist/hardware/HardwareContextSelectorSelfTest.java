package ghidrassist.hardware;

/** Offline hardware-RAG selection tests; never store or transmit private ECU images. */
public final class HardwareContextSelectorSelfTest {
    private static void ok(boolean value,String cause){if(!value)throw new AssertionError(cause);}
    public static void main(String[] args){
        String markdown="# Hardware Evidence — READ ONLY\n"+
            "- MCU identity: NOT VERIFIED\n\n"+
            "### fun_reset @ 0x2BC0\n\n"+
            "- SIMCR 0xFFFA00 = 0x40CA; tentative MM=1\n"+
            "- CSBAR7 0xFFFA68 = 0xFF88; CS7 0xFF8800..0xFF8FFF\n\n"+
            "### telemetry @ 0x12340\n\n"+
            "- Temperature calibration and sensor values\n\n"+
            "### app_initialize_hardware @ 0x6E968\n\n"+
            "- CSBAR7 0xFFFA68 = 0xFF88; CS7 speculative\n";
        String query="Jak skonfigurowano CSBAR7 i SIMCR?";
        String result=HardwareContextSelector.select(markdown,query,700);
        ok(result.contains("CSBAR7"),"relevant chip-select must appear");
        ok(result.contains("NOT confirmed"),"never assert physical identity");
        ok(result.contains("untrusted evidence DATA"),"RAG context remains untrusted data");
        ok(result.length()<=700,"token-size guard");
        ok(!HardwareContextSelector.select("",query,1000).contains("SIMCR"),
            "no fabricated facts");
        ok(HardwareContextSelector.select(markdown,query,100).isEmpty(),
            "reject tiny context budgets");
        String longReport="# Hardware Evidence — READ ONLY\n"+
            "### telemetry @ 0x1200\n"+
            "- Temperature sensor calibration and unrelated variables\n\n"+
            "### config_sim @ 0x2BCA\n"+
            "- SIMCR at 0xFFFA00 value 0x40CA; mapping candidate not runtime fact\n\n"+
            "### config_chip_selects @ 0x2BD2\n"+
            "- CSBAR7 at 0xFFFA68 value 0xFF88; candidate CS7\n";
        String focused=HardwareContextSelector.select(longReport,
            "Find SIMCR initialization",2400);
        ok(focused.contains("SIMCR") && !focused.contains("sensor calibration") &&
            !focused.contains("CSBAR7 at"),
            "focused query omits unrelated hardware and telemetry sections");
        ok(focused.contains("not instructions") && focused.contains("NOT confirmed"),
            "evidence always separated from instructions and verified facts");
        String broad=HardwareContextSelector.select(longReport,
            "unmatched unspecified question",2400);
        ok(broad.contains("<<<END_LOCAL_GHIDRA_HARDWARE_EVIDENCE>>>"),
            "no-match query still has a closed evidence boundary");
        String large="# Hardware Evidence — read-only\n"+
            "## Function-local evidence\n"+
            "### FUN_00002bc0 @ 00002bc0\n"+
            "- `00002bca` SIMCR `0xFFFA00` — WRITE; 0x40CA; move.w #0x40ca,(0x00fffa00).l\n"+
            ("- other register evidence in this function\n").repeat(80)+
            "### FUN_00009c96 @ 00009c96\n"+
            "- `00009c98` SIMCR `0xFFFA00` — WRITE; 0x4848; move.w #0x4848,(0x00fffa00).l\n"+
            "### FUN_0006e968 @ 0006e968\n"+
            "- `0006e96c` SIMCR `0xFFFA00` — WRITE; 0x40CA; move.w #0x40ca,(0x00fffa00).l\n";
        String full=HardwareContextSelector.select(large,"#hardware SIMCR MM",1200);
        ok(full.contains("00002bca")&&full.contains("00009c98")&&full.contains("0006e96c"),
            "all three SIMCR write sites must survive before long function details");
        ok(full.contains("3 of 3 matched sites") && full.length()<=1200,
            "complete coverage and bounded size");
        String doubled="# Hardware Evidence\n"+
            "### FUN_00002bc0 @ 00002bc0\n"+
            "- `00002bca` SIMCR `0xFFFA00` — WRITE; 0x40CA; move.w #0x40ca,(0x00fffa00).l\n"+
            "### FUN_00009c96 @ 00009c96\n"+
            "- `00009c98` SIMCR `0xFFFA00` — WRITE; 0x4848; move.w #0x4848,(0x00fffa00).l\n"+
            "### FUN_0006e968 @ 0006e968\n"+
            "- `0006e96c` SIMCR `0xFFFA00` — WRITE; 0x40CA; move.w #0x40ca,(0x00fffa00).l\n"+
            "## CFG/P-code hardware evidence\n"+
            "### FUN_00002bc0 at 00002bc0\n"+
            "- PC 0x002BCA: SIMCR at 0xFFFA00 [direct/P-code] value 0x40CA\n"+
            "### FUN_00009c96 at 00009c96\n"+
            "- PC 0x009C98: SIMCR at 0xFFFA00 [direct/P-code] value 0x4848\n"+
            "### FUN_0006e968 at 0006e968\n"+
            "- PC 0x06E96C: SIMCR at 0xFFFA00 [direct/P-code] value 0x40CA\n";
        String deduped=HardwareContextSelector.select(doubled,"#hardware SIMCR MM",2000);
        ok(deduped.contains("matched unique instruction/register sites=3"),
            "Listing and P-code must not double-count the same instruction");
        ok(deduped.contains("3 of 3 matched sites included"),
            "coverage must count actual unique sites");
        ok(!deduped.contains("PC 0x002BCA:"),
            "prefer original disassembly evidence over repeated P-code entry");
        String cited=HardwareBitfieldSourceLedger.inspect(
            HardwareProfiles.mc68332()).markdown()+
            "## Function-local evidence\n"+
            "### reset @ 00002bc0\n"+
            "- `00002bca` SIMCR `0xFFFA00` WRITE 0x40CA\n"+
            "- `00003010` SYNCR `0xFFFA04` WRITE 0xD084\n";
        String simRag=HardwareContextSelector.select(cited,"#hardware SIMCR",5000);
        ok(simRag.contains("| SIMCR | SHEN |") &&
            simRag.contains("| SIMCR | MM |") &&
            simRag.contains("FIELD PAGE CLAIM COVERAGE: 8 of 8") &&
            simRag.contains("PDF BYTES/EDITION UNVERIFIED") &&
            !simRag.contains("| SYNCR | W |"),
            "focused SIMCR RAG must retain all eight source-page claims only");
        String synRag=HardwareContextSelector.select(cited,"#hardware SYNCR",5000);
        ok(synRag.contains("| SYNCR | STEXT |") &&
            synRag.contains("FIELD PAGE CLAIM COVERAGE: 7 of 7") &&
            !synRag.contains("| SIMCR | MM |"),
            "SYNCR RAG source citations must remain register-specific");
        String shortRag=HardwareContextSelector.select(cited,"#hardware SIMCR",700);
        ok(shortRag.contains("FIELD PAGE CLAIM COVERAGE:") &&
            shortRag.contains("<<<END_LOCAL_GHIDRA_HARDWARE_EVIDENCE>>>") &&
            shortRag.length()<=700,
            "bounded RAG explicitly reports omitted field citations");

        // A real selected-MCU full report has 12 independent conditional CS
        // rows, but the old fast register-site RAG path returned before
        // any of these source-scoped rows could reach the question.
        String sourceHeader=
            "#### Function-local MC68332 CSBOOT/CS0–CS10 source snapshot (NOT active hardware)\n\n";
        String sourceTail=
            ". Selection uses source coverage/PC only, NOT execution order, "+
            "first/last write or physical CS assertion.\n\n";
        String firstTable=sourceHeader+
            "- SOURCE PC 0x000050; possible SIM mapping MM1; "+
            "one retained CFG context of 1; known 16-bit CS words 1"+
            sourceTail+
            ChipSelectTable.markdown(java.util.Map.of("CSBAR0",0xf803),true);
        String secondTable=sourceHeader+
            "- SOURCE PC 0x000070; possible SIM mapping MM0; "+
            "one retained CFG context of 1; known 16-bit CS words 1"+
            sourceTail+
            ChipSelectTable.markdown(java.util.Map.of("CSBAR7",0xff83),true);
        String focusedCs=HardwareContextSelector.select(
            firstTable+secondTable,"#hardware CSBAR0 map",5000);
        ok(focusedCs.contains("SOURCE PC 0x000050") &&
            !focusedCs.contains("SOURCE PC 0x000070") &&
            focusedCs.contains("CS TABLE ROW COVERAGE: 12 of 12") &&
            focusedCs.contains("other valid source contexts omitted=1") &&
            focusedCs.contains(
                "| CS0 | 0xF80000 | 0xF8FFFF | 64 KiB | 0xF803 | "+
                "UNKNOWN | UNKNOWN | PARTIAL: CSOR/CSPAR unknown |") &&
            focusedCs.contains("| CS10 | UNKNOWN | UNKNOWN | UNKNOWN |") &&
            !focusedCs.contains("CONDITIONAL: possible assertion") &&
            focusedCs.contains("NOT a combined map"),
            "focused RAG must retain one full CSBAR0 snapshot with source "+
            "PC/MM and all 12 conditional rows, not combine function sources");
        String cs7=HardwareContextSelector.select(firstTable+secondTable,
            "#hardware CSBAR7",5000);
        ok(cs7.contains("SOURCE PC 0x000070") &&
            !cs7.contains("SOURCE PC 0x000050") &&
            cs7.contains("| CS7 |") &&
            cs7.contains("12 of 12"),
            "requested register with known value outranks unrelated function");
        String reversedCs=HardwareContextSelector.select(
            secondTable+firstTable,"#hardware CSBAR0",5000);
        ok(reversedCs.contains("SOURCE PC 0x000050") &&
            !reversedCs.contains("SOURCE PC 0x000070"),
            "source selection independent of report function traversal order");
        String withSites=firstTable+
            "## Listing/XREF inventory\n"+
            "### FUN_00000050\n"+
            "- PC 0x000050: CSBAR0 at 0xFFFA4C [direct/P-code] value 0xF803\n"+
            "### FUN_00000020\n"+
            "- PC 0x000020: SIMCR at 0xFFFA00 [direct/P-code] value 0x40CA\n";
        String csWithSite=HardwareContextSelector.select(
            withSites,"#hardware CSBAR0",5000);
        ok(csWithSite.contains("CS TABLE ROW COVERAGE: 12 of 12") &&
            csWithSite.contains("matched unique instruction/register sites=1") &&
            csWithSite.contains("PC 0x000050: CSBAR0"),
            "fast matched register-site route must not omit matching CS table");
        String simWithCs=HardwareContextSelector.select(
            withSites,"#hardware SIMCR",5000);
        ok(simWithCs.contains("PC 0x000020: SIMCR") &&
            !simWithCs.contains("CS TABLE SOURCE SNAPSHOT"),
            "SIMCR-only query must not consume budget for unrelated CS table");
        String shortCs=HardwareContextSelector.select(
            withSites,"#hardware CSBAR0",1400);
        ok(shortCs.length()<=1400 &&
            shortCs.contains("<<<END_LOCAL_GHIDRA_HARDWARE_EVIDENCE>>>") &&
            (shortCs.contains("CS TABLE ROW COVERAGE:") ||
                shortCs.contains("CS TABLE CONTEXT:")) &&
            !shortCs.contains("CS TABLE ROW COVERAGE: 12 of 12"),
            "tight context reports bounded subset/omission, never fake full table");
        String brokenCs=firstTable.replace(
            "| CS10 | UNKNOWN | UNKNOWN | UNKNOWN |",
            "| CS11 | UNKNOWN | UNKNOWN | UNKNOWN |");
        String refused=HardwareContextSelector.select(
            brokenCs,"#hardware CSBAR0",5000);
        ok(refused.contains("no complete, distinct 12-row") &&
            !refused.contains("CS TABLE ROW COVERAGE: 12 of 12"),
            "malformed 12-select source cannot become complete RAG evidence");
        String genericCs=HardwareContextSelector.select(
            "# Generic CPU32 — no MC68332 profile\n", "#hardware CSBAR0",5000);
        ok(!genericCs.contains("CS TABLE SOURCE SNAPSHOT") &&
            !genericCs.contains("CS TABLE ROW COVERAGE"),
            "generic CPU32 must not inherit MC68332 CS source snapshots");

        System.out.println("HardwareContextSelectorSelfTest OK");
    }
}
