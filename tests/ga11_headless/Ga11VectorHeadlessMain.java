// Synthetic GA-11 real-Ghidra 12.1.4 headless integration; no private ECU bytes.
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;
import ghidrassist.hardware.GhidraInterruptVectorService;
import ghidrassist.hardware.GhidraHardwareFlowService;
import ghidrassist.hardware.HardwareInventoryService;
import ghidrassist.hardware.HardwareFlowStageCache;
import ghidrassist.hardware.HardwareAnalysisRevision;
import java.awt.GraphicsEnvironment;
import java.nio.file.*;
import java.util.*;

public final class Ga11VectorHeadlessMain {
    static class Manager extends DefaultProjectManager { Manager(){super();} }
    static final Gson JSON=new GsonBuilder().setPrettyPrinting().create();
    static void check(boolean pass,String why){
        if(!pass)throw new AssertionError(why);
    }
    static Address address(Program p,long value){
        return p.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    }
    static String row(String report,int vector) {
        String prefix="| "+vector+" | ";
        for(String line:report.split("\\R"))if(line.startsWith(prefix))return line;
        return "";
    }
    static void checkState(String line,String state) {
        check(!line.isEmpty()&&line.contains("| "+state+" |"),
            "Expected "+state+" in vector row: "+line);
    }
    static void expectUncertain(String report){
        check(report.contains("runtime VBR UNKNOWN"),"runtime VBR uncertainty absent");
        check(report.contains("STATIC DATA ONLY"),"static-only assertion absent");
        check(report.contains("not proof of an executable ISR"),
            "mapped target incorrectly asserted as runnable ISR");
        check(!report.contains("active ISR verified"),"false ISR assertion");
    }
    /** Test-only function definition; every transaction is on a disposable fixture. */
    static void defineFixtureFunction(Program program,long pc,int byteLength,String name)
            throws Exception {
        Address start=address(program,pc);
        int tx=program.startTransaction("GA18 test-only decoded MMIO source "+name);
        boolean commit=false;
        try {
            check(new DisassembleCommand(start,null,false)
                .applyTo(program,TaskMonitor.DUMMY),
                "Real Ghidra CPU32 disassembler rejected "+name);
            Function defined=program.getFunctionManager().createFunction(name,start,
                new AddressSet(start,start.add(byteLength-1)),SourceType.ANALYSIS);
            check(defined!=null && defined.getEntryPoint().equals(start),
                "Real Ghidra FunctionManager rejected "+name);
            commit=true;
        } finally { program.endTransaction(tx,commit); }
    }
    public static void main(String[] args)throws Exception {
        Path ghidra=Path.of(args[0]).toRealPath();
        Path projectDir=Path.of(args[1]).toRealPath();
        Path out=Path.of(args[2]).toRealPath();
        boolean strictEntry=Boolean.parseBoolean(args[3]);
        String ga18Mode=args.length>4?args[4]:"none";
        check(Set.of("none","overview","cache","startup","csbar","revision","simcr-alternatives","csbar-width",
            "csbar-independent","csbar-identical","csbar-unknown-word",
            "simcr-partial","vector-edit-undo","cache-program-isolation",
            "generic-profile","trambar-source","csbar-mm0-reject",
            "mmio-read-reference","csbar-csor-conditional",
            "simcr-mm0-literal","trambar-unknown","csor-alternatives",
            "branch-simcr","call-barrier","cancel-incomplete",
            "function-rename","apply-preserve","provenance-csv","movec-vbr").contains(ga18Mode),
            "Unknown GA-18 acceptance mode");
        var config=new HeadlessGhidraApplicationConfiguration();
        config.setApplicationLogFile(out.resolve("ghidra.log").toFile());
        Application.initializeApplication(new GhidraApplicationLayout(ghidra.toFile()),config);
        check(GraphicsEnvironment.isHeadless(),"Ghidra must really run headless");
        DefaultProjectManager manager=new Manager();
        Project project=manager.openProject(new ProjectLocator(
            projectDir.toString(),"Ga11Vectors"),false,false);
        AppInfo.setActiveProject(project);
        Object consumer=new Object();
        Program full=null,shortImage=null;
        JsonObject result=new JsonObject();
        result.addProperty("schema",1);
        result.addProperty("ghidra_version","12.1.4");
        result.addProperty("fixture_only",true);
        result.addProperty("actual_ghidra_program",true);
        result.addProperty("expect_exact_entry",strictEntry);
        result.addProperty("supervisor_ack",false);
        try {
            full=(Program)project.getProjectData().getFile("/vectors-full.bin")
                .getDomainObject(consumer,false,false,TaskMonitor.DUMMY);
            shortImage=(Program)project.getProjectData().getFile("/vectors-short.bin")
                .getDomainObject(consumer,false,false,TaskMonitor.DUMMY);
            check(full.getLanguageID().toString().startsWith("68000:BE:"),
                "Real CPU32 big-endian language required");
            check(full.getMemory().getSize()>=4096,"Synthetic memory not imported");
            Address entry=address(full,0x400L);
            int tx=full.startTransaction("synthetic test-only function definition");
            try {
                var d=new DisassembleCommand(entry,null,false);
                check(d.applyTo(full,TaskMonitor.DUMMY),
                    "Actual 68000 disassembler rejected synthetic NOP/RTS");
                Function fun=full.getFunctionManager().createFunction(
                    "synthetic_vector_handler",entry,
                    new AddressSet(entry,entry.add(5)),SourceType.ANALYSIS);
                check(fun!=null&&fun.getEntryPoint().equals(entry),
                    "Real Ghidra FunctionManager entry missing");
            } finally {full.endTransaction(tx,true);}
            check(full.getFunctionManager().getFunctionContaining(
                address(full,0x402L))!=null,
                "Interior target must be inside real Ghidra Function body");
            check(full.getFunctionManager().getFunctionAt(
                address(full,0x402L))==null,
                "Interior target must not be exact function entry");
            long before=full.getModificationNumber();
            String main=GhidraInterruptVectorService.analyze(full,TaskMonitor.DUMMY);
            expectUncertain(main);
            check(main.contains("Slots inspected: 254"),
                "Not all 254 vector slots scanned from actual Program");
            check(main.contains("Output truncated"),
                "Bounded output cap not reached by synthetic fixture");
            checkState(row(main,2),"RECOGNIZED_FUNCTION_CANDIDATE");
            checkState(row(main,4),"MAPPED_TARGET");
            checkState(row(main,5),"UNMAPPED_TARGET");
            checkState(row(main,6),"ODD_POINTER");
            check(row(main,7).isEmpty()&&row(main,8).isEmpty(),
                "Null/erased values must not become ISR rows");
            if(strictEntry){
                checkState(row(main,3),"INTERIOR_FUNCTION_POINTER_CANDIDATE");
                check(main.contains("pointers inside recognized function bodies (NOT entries): 1"),
                    "Interior-function count must remain separate");
            }else{
                // PR57 baseline did not yet distinguish interior entries.
                checkState(row(main,3),"RECOGNIZED_FUNCTION_CANDIDATE");
                check(!main.contains("INTERIOR_FUNCTION_POINTER_CANDIDATE"),
                    "PR57 baseline unexpectedly has PR80 classification");
            }
            check(full.getModificationNumber()==before,
                "Read-only vector service modified synthetic Ghidra Program");
            // Exercise the real production flow, not just the pure-Java model.
            String production=new GhidraHardwareFlowService()
                .analyze(full,TaskMonitor.DUMMY).markdown;
            check(production.contains("Exception / interrupt vector *candidates*") &&
                production.contains("runtime VBR UNKNOWN"),
                "Actual production flow did not include service vector report");
            check(full.getModificationNumber()==before,
                "Production Analyze wrote to the test Program");
            String shortReport=GhidraInterruptVectorService.analyze(
                shortImage,TaskMonitor.DUMMY);
            check(shortReport.contains("Slots inspected: 254") &&
                shortReport.contains("unreadable: 244"),
                "Short real memory import must classify missing slots UNREADABLE");
            expectUncertain(shortReport);
            if(!"none".equals(ga18Mode)) {
                // Optional synthetic-only integration against an ACTUAL
                // Ghidra Program. Existing vectors remain untouched.
                Address mmio=address(full,0x500L);
                int writeTx=full.startTransaction(
                    "GA18 TEST-ONLY synthetic SIMCR definition");
                try {
                    check(new DisassembleCommand(mmio,null,false)
                        .applyTo(full,TaskMonitor.DUMMY),
                        "Real CPU32 disassembler rejected synthetic SIMCR write");
                    Function mmioFunction=full.getFunctionManager().createFunction(
                        "synthetic_simcr_write",mmio,
                        new AddressSet(mmio,mmio.add(9)),SourceType.ANALYSIS);
                    check(mmioFunction!=null &&
                          mmioFunction.getEntryPoint().equals(mmio),
                        "Real synthetic SIMCR function entry absent");
                } finally { full.endTransaction(writeTx,true); }
                long hwBefore=full.getModificationNumber();
                if("overview".equals(ga18Mode)){
                    HardwareInventoryService inventoryService=
                        new HardwareInventoryService();
                    HardwareInventoryService.Report mc=
                        inventoryService.scan(full,true,TaskMonitor.DUMMY);
                    check(mc.sites.stream().anyMatch(site->
                            site.pc.equals(mmio) &&
                            "SIMCR".equals(site.register) &&
                            site.write && site.literal!=null &&
                            site.literal==0x40ca),
                        "Production MMIO inventory missed actual synthetic SIMCR");
                    String overview=mc.overviewMarkdown;
                    check(overview.contains("## 1. Initialization candidates") &&
                          overview.contains("## 2. Register write history") &&
                          overview.contains("## 3. Chip Select map"),
                        "Real inventory failed to render three-part overview");
                    check(overview.contains("SIMCR/MM sites:") &&
                          overview.contains("static evidence") &&
                          overview.contains("UNKNOWN"),
                        "Overview lost site count, source uncertainty, or labels");
                    check(mc.detailsMarkdown.contains("Full evidence") ||
                          mc.markdown.contains("## Review / Apply source-safety gate"),
                        "Real inventory missing detail or source-safety gate");
                    HardwareInventoryService.Report generic=
                        inventoryService.scan(full,false,TaskMonitor.DUMMY);
                    check(generic.overviewMarkdown.contains(
                            "CPU32 — address survey ONLY") &&
                          generic.overviewMarkdown.contains(
                            "No MC68332 CS ranges are asserted"),
                        "Generic CPU32 report claimed MC68332 hardware ranges");
                    check(full.getModificationNumber()==hwBefore,
                        "Real inventory overview modified synthetic Ghidra Program");
                    result.addProperty("synthetic_simcr_detected",true);
                    result.addProperty("overview_three_parts_verified",true);
                    result.addProperty("cpu32_scope_conservative",true);
                    Files.writeString(out.resolve("ga18-overview.md"),overview);
                    Files.writeString(out.resolve("ga18-overview-cpu32.md"),
                                      generic.overviewMarkdown);
                } else if("cache".equals(ga18Mode)){
                    HardwareAnalysisRevision revision=
                        HardwareAnalysisRevision.capture(
                            full,hwBefore,full.getLanguageID().toString(),
                            full.getExecutableSHA256(),true);
                    HardwareFlowStageCache.clear(full);
                    var first=HardwareFlowStageCache.loadOrAnalyze(
                        full,revision,TaskMonitor.DUMMY);
                    check(!first.reused(),
                        "After clear, first real CFG stage must be computed");
                    var second=HardwareFlowStageCache.loadOrAnalyze(
                        full,revision,TaskMonitor.DUMMY);
                    check(second.reused() && second.report()==first.report(),
                        "Matching Ghidra Program/revision must reuse completed CFG stage");
                    HardwareFlowStageCache.clear(full);
                    var third=HardwareFlowStageCache.loadOrAnalyze(
                        full,revision,TaskMonitor.DUMMY);
                    check(!third.reused() && third.report()!=first.report(),
                        "Explicit stage invalidation did not recompute");
                    HardwareAnalysisRevision generic=
                        HardwareAnalysisRevision.capture(
                            full,hwBefore,full.getLanguageID().toString(),
                            full.getExecutableSHA256(),false);
                    var otherMode=HardwareFlowStageCache.loadOrAnalyze(
                        full,generic,TaskMonitor.DUMMY);
                    check(!otherMode.reused(),
                        "Different MCU selection reused stale cache report");
                    check(full.getModificationNumber()==hwBefore,
                        "CFG stage computation/cache mutated synthetic Ghidra Program");
                    result.addProperty("cfg_stage_first_computed",true);
                    result.addProperty("cfg_stage_cache_reused",true);
                    result.addProperty("cfg_stage_clear_invalidated",true);
                    result.addProperty("cfg_stage_scope_isolated",true);
                } else if("simcr-alternatives".equals(ga18Mode)) {
                    // Two contradictory real decoded SIMCR words IN ONE
                    // function. Source order is not the MM write-once order.
                    int writeSites=full.startTransaction(
                        "GA18 test-only contradictory SIMCR fixture bytes");
                    boolean writeSitesCommit=false;
                    try {
                        byte[] opcodes=java.util.HexFormat.of().parseHex(
                            "33fc40ca00fffa0033fc484800fffa004e75");
                        full.getMemory().setBytes(address(full,0x560L),opcodes);
                        writeSitesCommit=true;
                    } finally { full.endTransaction(writeSites,writeSitesCommit); }
                    defineFixtureFunction(full,0x560L,18,
                        "synthetic_simcr_two_alternatives");
                    long afterSetup=full.getModificationNumber();
                    GhidraHardwareFlowService.Report realCfg=
                        new GhidraHardwareFlowService().analyze(
                            full,TaskMonitor.DUMMY,true);
                    check(realCfg.rawCfgMmioSites.stream().anyMatch(s->
                            s.pc()==0x560L && "SIMCR".equals(s.register()) &&
                            s.widthBits()==16 &&
                            Integer.valueOf(0x40ca).equals(s.literal())),
                        "Real CFG missed first competing SIMCR word");
                    check(realCfg.rawCfgMmioSites.stream().anyMatch(s->
                            s.pc()==0x568L && "SIMCR".equals(s.register()) &&
                            s.widthBits()==16 &&
                            Integer.valueOf(0x4848).equals(s.literal())),
                        "Real CFG missed second competing SIMCR word");
                    var mc=new HardwareInventoryService().scan(
                        full,true,TaskMonitor.DUMMY);
                    check(mc.markdown.contains("MULTIPLE_LITERAL_ALTERNATIVES") &&
                          mc.markdown.contains("0x40CA, 0x4848") &&
                          mc.markdown.contains("SIMCR/MM write-once caveat") &&
                          mc.markdown.contains("NOT the first executed write"),
                        "Competing source words were falsely reduced to MM latch");
                    check(mc.overviewMarkdown.contains("static evidence") &&
                          mc.markdown.contains("latched hardware value"),
                        "Source alternatives incorrectly imply hardware execution");
                    check(full.getModificationNumber()==afterSetup,
                        "SIMCR alternatives analysis modified real Program");
                    result.addProperty("simcr_real_two_literals_detected",true);
                    result.addProperty("simcr_same_function_alternatives",true);
                    result.addProperty("simcr_write_once_runtime_unknown",true);
                    result.addProperty("simcr_alternatives_read_only",true);
                    Files.writeString(out.resolve("ga18-simcr-alternatives.md"),
                                      mc.markdown);
                } else if("csbar-width".equals(ga18Mode)) {
                    // Control: an otherwise complete real 16-bit CSBAR
                    // literal is only a manual candidate. A real 8-bit
                    // write to that same register must poison the proposal.
                    defineFixtureFunction(full,0x520L,10,
                        "synthetic_csbar_width_positive_control");
                    var positive=new HardwareInventoryService().scan(
                        full,true,TaskMonitor.DUMMY);
                    check(positive.csbarReview.candidates().stream().anyMatch(c->
                            "CSBAR0".equals(c.register()) && c.word()==0x387c),
                        "Real positive control missing full-word CSBAR");
                    int widthTx=full.startTransaction(
                        "GA18 test-only byte-width CSBAR fixture");
                    boolean widthCommit=false;
                    try {
                        full.getMemory().setBytes(address(full,0x580L),
                            java.util.HexFormat.of().parseHex(
                                "13fc00ff00fffa4c4e75"));
                        widthCommit=true;
                    } finally {full.endTransaction(widthTx,widthCommit);}
                    defineFixtureFunction(full,0x580L,10,
                        "synthetic_csbar_byte_partial_write");
                    long beforeWidthScan=full.getModificationNumber();
                    GhidraHardwareFlowService.Report cfg=
                        new GhidraHardwareFlowService().analyze(
                            full,TaskMonitor.DUMMY,true);
                    check(cfg.rawCfgMmioSites.stream().anyMatch(s->
                            s.pc()==0x580L &&
                            "CSBAR0".equals(s.register()) &&
                            s.widthBits()==8),
                        "Real P-code missing byte-width CSBAR STORE evidence");
                    var poisoned=new HardwareInventoryService().scan(
                        full,true,TaskMonitor.DUMMY);
                    check(poisoned.csbarReview.candidates().isEmpty() &&
                          poisoned.csbarReview.uncertainSites()>0,
                        "Partial-width write promoted full CSBAR window");
                    check(poisoned.csbarReview.summary().contains(
                            "MM latch and actual chip-select assertion UNKNOWN"),
                        "CSBAR width review inferred real active hardware");
                    check(full.getModificationNumber()==beforeWidthScan,
                        "Width safety analysis changed disposable Program");
                    result.addProperty("csbar_real_byte_store_detected",true);
                    result.addProperty("csbar_partial_width_rejected",true);
                    result.addProperty("csbar_positive_control_retained",true);
                    result.addProperty("csbar_width_read_only",true);
                    Files.writeString(out.resolve("ga18-csbar-width.md"),
                                      poisoned.markdown);

                } else if("csbar-independent".equals(ga18Mode)) {
                    // Two different CSBAR index addresses must remain two
                    // *independent manual proposals*, never one CS map.
                    defineFixtureFunction(full,0x520L,10,"fixture_csbar0");
                    int t=full.startTransaction("GA18 fixture separate CSBAR1");
                    try {
                        full.getMemory().setBytes(address(full,0x5a0L),
                            java.util.HexFormat.of().parseHex(
                                "33fc387e00fffa504e75"));
                    } finally {full.endTransaction(t,true);}
                    defineFixtureFunction(full,0x5a0L,10,"fixture_csbar1");
                    long rev=full.getModificationNumber();
                    var report=new HardwareInventoryService().scan(
                        full,true,TaskMonitor.DUMMY);
                    check(report.csbarReview.candidates().size()==2 &&
                          report.csbarReview.candidates().stream().anyMatch(c->
                            "CSBAR0".equals(c.register()) && c.word()==0x387c) &&
                          report.csbarReview.candidates().stream().anyMatch(c->
                            "CSBAR1".equals(c.register()) && c.word()==0x387e),
                        "Independent register candidates were dropped/combined");
                    check(report.csbarReview.summary().contains(
                            "actual chip-select assertion UNKNOWN") &&
                          full.getModificationNumber()==rev,
                        "Separate source words became physical CS assertion or edited Program");
                    result.addProperty("csbar_two_registers_independently_detected",true);
                    result.addProperty("csbar_distinct_windows_not_combined",true);
                    result.addProperty("csbar_independent_scan_read_only",true);
                    Files.writeString(out.resolve("ga18-csbar-independent.md"),
                                      report.markdown);
                } else if("csbar-identical".equals(ga18Mode)) {
                    // Two distinct functions with identical full word are
                    // consistent but still *not* two physical assertions.
                    defineFixtureFunction(full,0x520L,10,"fixture_csbar_first");
                    int t=full.startTransaction("GA18 fixture repeated CSBAR0");
                    try {
                        full.getMemory().setBytes(address(full,0x5a0L),
                            java.util.HexFormat.of().parseHex(
                                "33fc387c00fffa4c4e75"));
                    } finally {full.endTransaction(t,true);}
                    defineFixtureFunction(full,0x5a0L,10,"fixture_csbar_repeat");
                    long rev=full.getModificationNumber();
                    var report=new HardwareInventoryService().scan(
                        full,true,TaskMonitor.DUMMY);
                    check(report.csbarReview.candidates().size()==1 &&
                          report.csbarReview.candidates().get(0).word()==0x387c &&
                          report.csbarReview.candidates().get(0)
                              .independentSiteCount()==2,
                        "Identical distinct source PCs not preserved as one reviewed candidate");
                    check(report.csbarReview.matchedSites()>=2 &&
                          report.csbarReview.summary().contains(
                              "until manual Review/Apply") &&
                          full.getModificationNumber()==rev,
                        "Repeat writes incorrectly activated CS or changed Program");
                    result.addProperty("csbar_identical_sources_collapsed_to_candidate",true);
                    result.addProperty("csbar_two_distinct_site_origins",true);
                    result.addProperty("csbar_repeated_source_read_only",true);
                } else if("csbar-unknown-word".equals(ga18Mode)) {
                    // Decoded MOVE.W D0,(CSBAR0) is 16 bits but value UNKNOWN.
                    defineFixtureFunction(full,0x520L,10,
                        "fixture_csbar_known_literal");
                    int t=full.startTransaction("GA18 fixture unknown D0 CSBAR");
                    try {
                        full.getMemory().setBytes(address(full,0x5a0L),
                            java.util.HexFormat.of().parseHex(
                                "33c000fffa4c4e75"));
                    } finally {full.endTransaction(t,true);}
                    defineFixtureFunction(full,0x5a0L,8,"fixture_csbar_d0_unknown");
                    long rev=full.getModificationNumber();
                    var cfg=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(cfg.rawCfgMmioSites.stream().anyMatch(site->
                            site.pc()==0x5a0L &&
                            "CSBAR0".equals(site.register()) &&
                            site.widthBits()==16 && site.literal()==null),
                        "Actual Ghidra P-code missed unknown-value full-word STORE");
                    var report=new HardwareInventoryService().scan(
                        full,true,TaskMonitor.DUMMY);
                    check(report.csbarReview.candidates().isEmpty() &&
                          report.csbarReview.uncertainSites()>0 &&
                          full.getModificationNumber()==rev,
                        "Unknown D0 16-bit word was guessed from earlier constant");
                    result.addProperty("csbar_unknown_word_real_pcode",true);
                    result.addProperty("csbar_unknown_word_blocks_proposal",true);
                    result.addProperty("csbar_unknown_word_read_only",true);
                    Files.writeString(out.resolve("ga18-csbar-unknown-word.md"),
                                      report.markdown);
                } else if("simcr-partial".equals(ga18Mode)) {
                    // Same recognized function writes a byte then a word:
                    // a byte store cannot establish a full SIMCR/MM snapshot.
                    int t=full.startTransaction("GA18 fixture partial SIMCR");
                    try {
                        full.getMemory().setBytes(address(full,0x5a0L),
                            java.util.HexFormat.of().parseHex(
                                "13fc00ff00fffa0033fc40ca00fffa004e75"));
                    } finally {full.endTransaction(t,true);}
                    defineFixtureFunction(full,0x5a0L,18,"fixture_simcr_byte_word");
                    long rev=full.getModificationNumber();
                    var cfg=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(cfg.rawCfgMmioSites.stream().anyMatch(site->
                            site.pc()==0x5a0L &&
                            "SIMCR".equals(site.register()) &&
                            site.widthBits()==8) &&
                          cfg.rawCfgMmioSites.stream().anyMatch(site->
                            site.pc()==0x5a8L &&
                            "SIMCR".equals(site.register()) &&
                            site.widthBits()==16 &&
                            Integer.valueOf(0x40ca).equals(site.literal())),
                        "Actual Ghidra P-code failed mixed-size SIMCR source capture");
                    var report=new HardwareInventoryService().scan(
                        full,true,TaskMonitor.DUMMY);
                    check(report.markdown.contains("UNKNOWN_WRITE_VALUE") &&
                          report.markdown.contains("SIMCR/MM write-once caveat") &&
                          report.markdown.contains("hardware value") &&
                          full.getModificationNumber()==rev,
                        "Partial SIMCR write was promoted to known runtime MM latch");
                    result.addProperty("simcr_real_partial_and_word_decoded",true);
                    result.addProperty("simcr_partial_unknown_alternative",true);
                    result.addProperty("simcr_partial_runtime_mm_unproven",true);
                    result.addProperty("simcr_partial_read_only",true);
                    Files.writeString(out.resolve("ga18-simcr-partial.md"),report.markdown);
                } else if("vector-edit-undo".equals(ga18Mode)) {
                    // Source-image vector slot changes must be observed,
                    // with native Ghidra Undo, no stale ISR claims.
                    Address slot=address(full,16L); // vector #4
                    byte[] original=new byte[4];
                    full.getMemory().getBytes(slot,original);
                    String baseline=GhidraInterruptVectorService.analyze(
                        full,TaskMonitor.DUMMY);
                    checkState(row(baseline,4),"MAPPED_TARGET");
                    int t=full.startTransaction("GA18 synthetic vector rewrite");
                    try {
                        full.getMemory().setBytes(slot,
                            java.util.HexFormat.of().parseHex("00000400"));
                    } finally {full.endTransaction(t,true);}
                    long changed=full.getModificationNumber();
                    String modified=GhidraInterruptVectorService.analyze(
                        full,TaskMonitor.DUMMY);
                    checkState(row(modified,4),"RECOGNIZED_FUNCTION_CANDIDATE");
                    expectUncertain(modified);
                    check(changed==full.getModificationNumber(),
                        "Vector scan mutated Ghidra Program");
                    check(full.canUndo(),"Native Ghidra Undo unavailable for vector edit");
                    full.undo();
                    byte[] restored=new byte[4];
                    full.getMemory().getBytes(slot,restored);
                    check(java.util.Arrays.equals(restored,original),
                        "Native Ghidra Undo did not restore vector source bytes");
                    long undone=full.getModificationNumber();
                    String again=GhidraInterruptVectorService.analyze(
                        full,TaskMonitor.DUMMY);
                    checkState(row(again,4),"MAPPED_TARGET");
                    check(full.getModificationNumber()==undone,
                        "Vector re-scan edited Program after Undo");
                    expectUncertain(again);
                    result.addProperty("vector_real_edit_reclassified",true);
                    result.addProperty("vector_native_undo_restored",true);
                    result.addProperty("vector_runtime_vbr_unproven",true);
                    result.addProperty("vector_scan_after_undo_read_only",true);
                } else if("cache-program-isolation".equals(ga18Mode)) {
                    // Two real Program instances share JVM and classloader
                    // but may not share a completed CFG cache.
                    HardwareFlowStageCache.clear(full);
                    HardwareFlowStageCache.clear(shortImage);
                    long shortRev=shortImage.getModificationNumber();
                    var longInput=HardwareAnalysisRevision.capture(
                        full,hwBefore,full.getLanguageID().toString(),
                        full.getExecutableSHA256(),true);
                    var shortInput=HardwareAnalysisRevision.capture(
                        shortImage,shortRev,shortImage.getLanguageID().toString(),
                        shortImage.getExecutableSHA256(),true);
                    var first=HardwareFlowStageCache.loadOrAnalyze(
                        full,longInput,TaskMonitor.DUMMY);
                    var second=HardwareFlowStageCache.loadOrAnalyze(
                        shortImage,shortInput,TaskMonitor.DUMMY);
                    check(!first.reused() && !second.reused() &&
                          first.report()!=second.report(),
                        "Different genuine Ghidra Programs shared cached CFG stage");
                    check(HardwareFlowStageCache.loadOrAnalyze(
                            full,longInput,TaskMonitor.DUMMY).reused() &&
                          HardwareFlowStageCache.loadOrAnalyze(
                            shortImage,shortInput,TaskMonitor.DUMMY).reused(),
                        "Stable separate Ghidra Program revisions did not reuse cache");
                    var forged=HardwareAnalysisRevision.capture(
                        full,shortRev,shortImage.getLanguageID().toString(),
                        shortImage.getExecutableSHA256(),true);
                    try {
                        HardwareFlowStageCache.loadOrAnalyze(
                            shortImage,forged,TaskMonitor.DUMMY);
                        throw new AssertionError(
                            "Wrong Program identity accepted despite matching revision fields");
                    } catch(CancelledException expected) { /* fail closed */ }
                    check(full.getModificationNumber()==hwBefore &&
                          shortImage.getModificationNumber()==shortRev,
                        "Cross-program cache test wrote test data");
                    result.addProperty("cache_real_two_programs_isolated",true);
                    result.addProperty("cache_each_revision_reused_only_locally",true);
                    result.addProperty("cache_wrong_identity_fail_closed",true);
                    result.addProperty("cache_cross_program_read_only",true);
                } else if("generic-profile".equals(ga18Mode)) {
                    // No concrete model selected means no MC68332 hardware
                    // Review proposals, even with actual decoded CSBAR site.
                    defineFixtureFunction(full,0x520L,10,
                        "fixture_generic_cpu32_csbar_candidate");
                    long rev=full.getModificationNumber();
                    var mc=new HardwareInventoryService().scan(
                        full,true,TaskMonitor.DUMMY);
                    check(mc.csbarReview.candidates().stream().anyMatch(c->
                            "CSBAR0".equals(c.register()) && c.word()==0x387c),
                        "Concrete-MCU source control absent");
                    var generic=new HardwareInventoryService().scan(
                        full,false,TaskMonitor.DUMMY);
                    check(generic.csbarReview.candidates().isEmpty() &&
                          generic.overviewMarkdown.contains(
                              "CPU32 — address survey ONLY") &&
                          generic.overviewMarkdown.contains(
                              "No MC68332 CS ranges are asserted") &&
                          generic.csbarReview.summary().contains(
                              "model selected: false") &&
                          full.getModificationNumber()==rev,
                        "Unselected MCU inherited concrete CSBAR Review or edited Program");
                    result.addProperty("generic_cpu32_kept_address_only",true);
                    result.addProperty("generic_mc68332_csbar_proposals_disabled",true);
                    result.addProperty("generic_model_switch_read_only",true);

                } else if("trambar-source".equals(ga18Mode)) {
                    // The TPU RAM base is a conditional literal sketch,
                    // never proof of physical RAM enablement.
                    int t=full.startTransaction("GA18 synthetic TRAMBAR literal");
                    try {
                        full.getMemory().setBytes(address(full,0x5a0L),
                            java.util.HexFormat.of().parseHex(
                                "33fcfff000fffb044e75"));
                    } finally {full.endTransaction(t,true);}
                    defineFixtureFunction(full,0x5a0L,10,"fixture_trambar_word");
                    long rev=full.getModificationNumber();
                    var cfg=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(cfg.rawCfgMmioSites.stream().anyMatch(site->
                            site.pc()==0x5a0L &&
                            "TRAMBAR".equals(site.register()) &&
                            site.widthBits()==16 &&
                            Integer.valueOf(0xfff0).equals(site.literal())),
                        "Genuine Ghidra CPU32 TRAMBAR word source missing");
                    check(cfg.markdown.contains("possible MC68332 TPURAM=") &&
                          cfg.markdown.contains("not active until MCU/reset state verified"),
                        "Literal TRAMBAR incorrectly promoted to enabled RAM");
                    var report=new HardwareInventoryService().scan(
                        full,true,TaskMonitor.DUMMY);
                    check(report.markdown.contains("TRAMBAR") &&
                          report.markdown.contains("STATIC POSSIBILITY") &&
                          full.getModificationNumber()==rev,
                        "TRAMBAR source incorrectly asserted runtime state or edited Program");
                    result.addProperty("trambar_real_word_literal_decoded",true);
                    result.addProperty("trambar_conditional_window_only",true);
                    result.addProperty("trambar_real_analysis_read_only",true);
                } else if("csbar-mm0-reject".equals(ga18Mode)) {
                    // A source address in MM0 may be statically matched but
                    // must never inherit MM1-specific safe Review candidates.
                    int t=full.startTransaction("GA18 synthetic MM0 CSBAR");
                    try {
                        full.getMemory().setBytes(address(full,0x5a0L),
                            java.util.HexFormat.of().parseHex(
                                "33fc387c007ffa4c4e75"));
                    } finally {full.endTransaction(t,true);}
                    defineFixtureFunction(full,0x5a0L,10,"fixture_csbar0_mm0");
                    long rev=full.getModificationNumber();
                    var cfg=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(cfg.rawCfgMmioSites.stream().anyMatch(site->
                            site.pc()==0x5a0L &&
                            site.address()==0x7ffa4cL &&
                            "CSBAR0".equals(site.register()) &&
                            Integer.valueOf(0x387c).equals(site.literal())),
                        "Genuine Ghidra CFG lost MM0 CSBAR candidate source");
                    var report=new HardwareInventoryService().scan(
                        full,true,TaskMonitor.DUMMY);
                    check(report.csbarReview.candidates().isEmpty() &&
                          report.csbarReview.matchedSites()>0 &&
                          report.markdown.contains("conditional candidate snapshot") &&
                          full.getModificationNumber()==rev,
                        "MM0 CSBAR source was used to define MM1 Review memory window");
                    result.addProperty("csbar_mm0_actual_source_decoded",true);
                    result.addProperty("csbar_mm0_unsafe_review_rejected",true);
                    result.addProperty("csbar_mm0_analysis_read_only",true);
                } else if("mmio-read-reference".equals(ga18Mode)) {
                    // MOVE.W (CSBAR0),D0 is a read, not a write.
                    // The positive control at 0x520 remains a single proposal.
                    defineFixtureFunction(full,0x520L,10,"fixture_csbar0_write_control");
                    int t=full.startTransaction("GA18 synthetic CSBAR read");
                    try {
                        full.getMemory().setBytes(address(full,0x5a0L),
                            java.util.HexFormat.of().parseHex(
                                "303900fffa4c4e75"));
                    } finally {full.endTransaction(t,true);}
                    defineFixtureFunction(full,0x5a0L,8,"fixture_csbar0_read_only");
                    check(full.getListing().getInstructionAt(
                        address(full,0x5a0L)).getMnemonicString()
                        .equalsIgnoreCase("MOVE.W"),
                        "Real Ghidra did not disassemble memory read");
                    long rev=full.getModificationNumber();
                    var cfg=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(cfg.rawCfgMmioSites.stream().noneMatch(site->
                            site.pc()==0x5a0L && "CSBAR0".equals(site.register())),
                        "Actual read-only instruction misclassified as CFG STORE");
                    var report=new HardwareInventoryService().scan(
                        full,true,TaskMonitor.DUMMY);
                    check(report.csbarReview.candidates().size()==1 &&
                          "CSBAR0".equals(
                              report.csbarReview.candidates().get(0).register()) &&
                          report.csbarReview.candidates().get(0).word()==0x387c &&
                          full.getModificationNumber()==rev,
                        "Read reference poisoned or promoted a CSBAR write");
                    result.addProperty("mmio_real_read_disassembled",true);
                    result.addProperty("mmio_read_not_cfg_store",true);
                    result.addProperty("mmio_read_does_not_change_review",true);
                    result.addProperty("mmio_read_analysis_read_only",true);
                } else if("csbar-csor-conditional".equals(ga18Mode)) {
                    // Two required CS source registers in separate functions
                    // are not one simultaneous active physical configuration.
                    defineFixtureFunction(full,0x520L,10,"fixture_csbar0_source");
                    int t=full.startTransaction("GA18 synthetic CSOR0");
                    try {
                        full.getMemory().setBytes(address(full,0x5a0L),
                            java.util.HexFormat.of().parseHex(
                                "33fc7c3000fffa4e4e75"));
                    } finally {full.endTransaction(t,true);}
                    defineFixtureFunction(full,0x5a0L,10,"fixture_csor0_source");
                    long rev=full.getModificationNumber();
                    var cfg=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(cfg.rawCfgMmioSites.stream().anyMatch(site->
                            site.pc()==0x520L &&
                            "CSBAR0".equals(site.register()) &&
                            Integer.valueOf(0x387c).equals(site.literal())) &&
                          cfg.rawCfgMmioSites.stream().anyMatch(site->
                            site.pc()==0x5a0L &&
                            "CSOR0".equals(site.register()) &&
                            Integer.valueOf(0x7c30).equals(site.literal())),
                        "Actual Ghidra disassembly missed CSBAR0/CSOR0 sources");
                    var report=new HardwareInventoryService().scan(
                        full,true,TaskMonitor.DUMMY);
                    check(report.markdown.contains("CSBAR0") &&
                          report.markdown.contains("CSOR0") &&
                          report.markdown.contains("one simultaneous active CS map") &&
                          report.csbarReview.candidates().stream().anyMatch(c->
                              "CSBAR0".equals(c.register()) && c.word()==0x387c) &&
                          report.csbarReview.summary().contains(
                              "actual chip-select assertion UNKNOWN") &&
                          full.getModificationNumber()==rev,
                        "Separate CS source sites were incorrectly combined as active hardware");
                    result.addProperty("csbar_csor_real_sources_detected",true);
                    result.addProperty("csbar_csor_not_active_cs_map",true);
                    result.addProperty("csbar_csor_review_manual_only",true);
                    result.addProperty("csbar_csor_analysis_read_only",true);

                } else if("simcr-mm0-literal".equals(ga18Mode)) {
                    // Source-only MM=0 word candidate. Hardware MM is still
                    // write-once and unknown at runtime.
                    int t=full.startTransaction("GA18 SIMCR zero-word fixture");
                    try {
                        full.getMemory().setBytes(address(full,0x5a0L),
                            java.util.HexFormat.of().parseHex(
                                "33fc000000fffa004e75"));
                    } finally {full.endTransaction(t,true);}
                    defineFixtureFunction(full,0x5a0L,10,"fixture_simcr_mm0_word");
                    long rev=full.getModificationNumber();
                    var cfg=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(cfg.rawCfgMmioSites.stream().anyMatch(site->
                            site.pc()==0x5a0L &&
                            "SIMCR".equals(site.register()) &&
                            site.widthBits()==16 &&
                            Integer.valueOf(0).equals(site.literal())),
                        "Real P-code did not preserve SIMCR zero-word literal");
                    check(cfg.markdown.contains("candidate MM=0") &&
                          cfg.markdown.contains("first successful write UNKNOWN"),
                        "SIMCR zero word falsely became runtime MM state");
                    check(full.getModificationNumber()==rev,
                        "SIMCR zero literal scan mutated Ghidra project");
                    result.addProperty("simcr_mm0_real_word_zero_detected",true);
                    result.addProperty("simcr_mm0_source_not_runtime_latch",true);
                    result.addProperty("simcr_mm0_scan_read_only",true);
                } else if("trambar-unknown".equals(ga18Mode)) {
                    // A known width but unknown D0 value must not establish
                    // even a conditional TPURAM base.
                    int t=full.startTransaction("GA18 unknown TRAMBAR fixture");
                    try {
                        full.getMemory().setBytes(address(full,0x5a0L),
                            java.util.HexFormat.of().parseHex(
                                "33c000fffb044e75"));
                    } finally {full.endTransaction(t,true);}
                    defineFixtureFunction(full,0x5a0L,8,"fixture_trambar_from_d0");
                    long rev=full.getModificationNumber();
                    var cfg=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(cfg.rawCfgMmioSites.stream().anyMatch(site->
                            site.pc()==0x5a0L &&
                            "TRAMBAR".equals(site.register()) &&
                            site.widthBits()==16 && site.literal()==null),
                        "Real P-code incorrectly invented D0-to-TRAMBAR word");
                    check(!cfg.markdown.contains("possible MC68332 TPURAM=") &&
                          cfg.markdown.contains("TRAMBAR") &&
                          full.getModificationNumber()==rev,
                        "Unknown-word TRAMBAR incorrectly yielded SRAM address");
                    result.addProperty("trambar_unknown_real_word_detected",true);
                    result.addProperty("trambar_unknown_no_ram_window",true);
                    result.addProperty("trambar_unknown_scan_read_only",true);
                } else if("csor-alternatives".equals(ga18Mode)) {
                    // Conflicting CSOR0 literal writes within one Ghidra
                    // function cannot become one active chip-select timing.
                    int t=full.startTransaction("GA18 dual-CSOR0 fixture");
                    try {
                        full.getMemory().setBytes(address(full,0x5a0L),
                            java.util.HexFormat.of().parseHex(
                                "33fc7c3000fffa4e33fc7c3200fffa4e4e75"));
                    } finally {full.endTransaction(t,true);}
                    defineFixtureFunction(full,0x5a0L,18,"fixture_csor_two_words");
                    long rev=full.getModificationNumber();
                    var cfg=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(cfg.rawCfgMmioSites.stream().anyMatch(site->
                            site.pc()==0x5a0L &&
                            "CSOR0".equals(site.register()) &&
                            Integer.valueOf(0x7c30).equals(site.literal())) &&
                          cfg.rawCfgMmioSites.stream().anyMatch(site->
                            site.pc()==0x5a8L &&
                            "CSOR0".equals(site.register()) &&
                            Integer.valueOf(0x7c32).equals(site.literal())),
                        "Decoded competing CSOR0 literal writes missing");
                    var report=new HardwareInventoryService().scan(
                        full,true,TaskMonitor.DUMMY);
                    check(report.markdown.contains("MULTIPLE_LITERAL_ALTERNATIVES") &&
                          report.markdown.contains("0x7C30, 0x7C32") &&
                          report.markdown.contains(
                              "NOT one simultaneous active CS map") &&
                          full.getModificationNumber()==rev,
                        "Conflicting CSOR source values falsely collapsed or edited");
                    result.addProperty("csor_two_real_words_detected",true);
                    result.addProperty("csor_conflicting_alternatives_preserved",true);
                    result.addProperty("csor_no_active_map_inferred",true);
                    result.addProperty("csor_alternative_scan_read_only",true);

                } else if("branch-simcr".equals(ga18Mode)) {
                    // BNE skips the first full word, BRA skips the second.
                    // Both are possible first source sites, never a hardware
                    // execution trace or the first write-once MM latch.
                    int t=full.startTransaction("GA18 A synthetic CFG branch");
                    try {
                        full.getMemory().setBytes(address(full,0x5a0L),
                            java.util.HexFormat.of().parseHex(
                                "660a33fc40ca00fffa00600833fc484800fffa004e75"));
                    } finally {full.endTransaction(t,true);}
                    defineFixtureFunction(full,0x5a0L,22,
                        "fixture_branch_simcr_alternatives");
                    long rev=full.getModificationNumber();
                    var cfg=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(cfg.rawCfgMmioSites.stream().anyMatch(site->
                            site.pc()==0x5a2L && "SIMCR".equals(site.register()) &&
                            Integer.valueOf(0x40ca).equals(site.literal())) &&
                          cfg.rawCfgMmioSites.stream().anyMatch(site->
                            site.pc()==0x5acL && "SIMCR".equals(site.register()) &&
                            Integer.valueOf(0x4848).equals(site.literal())),
                        "Real conditional CPU32 SIMCR branches lost literal evidence");
                    check(cfg.markdown.contains("Possible first SIMCR source sites") &&
                          cfg.markdown.contains("0x000005A2") &&
                          cfg.markdown.contains("0x000005AC") &&
                          cfg.markdown.contains("MM write-once"),
                        "Alternative branch sites falsely reduced to an MM latch");
                    check(full.getModificationNumber()==rev,
                        "CFG alternatives analyzer modified Ghidra Program");
                    result.addProperty("branch_real_cfg_two_sources",true);
                    result.addProperty("branch_local_first_alternatives",true);
                    result.addProperty("branch_runtime_mm_unknown",true);
                    result.addProperty("branch_read_only",true);
                } else if("call-barrier".equals(ga18Mode)) {
                    // A0 is initially derived from SIMCR; the JSR may clobber
                    // it. The subsequent indirect write must not re-use
                    // a pre-call constant or turn it into a known MM word.
                    int t=full.startTransaction("GA18 A call barrier fixture");
                    try {
                        full.getMemory().setBytes(address(full,0x5a0L),
                            java.util.HexFormat.of().parseHex(
                                "207c00fffa004eb90000040030bc40ca4e75"));
                    } finally {full.endTransaction(t,true);}
                    defineFixtureFunction(full,0x5a0L,18,"fixture_simcr_call_barrier");
                    long rev=full.getModificationNumber();
                    var cfg=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(cfg.rawCfgMmioSites.stream().anyMatch(site->
                            site.pc()==0x5acL &&
                            "UNRESOLVED_ALIAS".equals(site.register()) &&
                            site.indirect()),
                        "Unknown call failed to invalidate A0 MMIO pointer");
                    check(cfg.rawCfgMmioSites.stream().noneMatch(site->
                            site.pc()==0x5acL && "SIMCR".equals(site.register()) &&
                            Integer.valueOf(0x40ca).equals(site.literal())),
                        "Indirect SIMCR constant was invented across CALL");
                    var inventory=new HardwareInventoryService().scan(
                        full,true,TaskMonitor.DUMMY);
                    check(inventory.csbarReview.candidates().isEmpty() &&
                          full.getModificationNumber()==rev,
                        "Unresolved call alias promoted unsafe CSBAR Review");
                    result.addProperty("call_real_jsr_barrier",true);
                    result.addProperty("call_clobbered_pointer_not_reused",true);
                    result.addProperty("call_alias_blocks_review",true);
                    result.addProperty("call_read_only",true);
                } else if("cancel-incomplete".equals(ga18Mode)) {
                    // Deterministic cancellation *during* a real Ghidra
                    // traversal (not only before entry). No partial report
                    // may be published as completed CFG/RAG evidence.
                    HardwareFlowStageCache.clear(full);
                    ghidrassist.hardware.HardwareEvidenceCache.clear(full);
                    long rev=full.getModificationNumber();
                    HardwareAnalysisRevision started=HardwareAnalysisRevision.capture(
                        full,rev,full.getLanguageID().toString(),
                        full.getExecutableSHA256(),true);
                    java.util.concurrent.atomic.AtomicInteger checks=
                        new java.util.concurrent.atomic.AtomicInteger();
                    TaskMonitor cancelling=(TaskMonitor)java.lang.reflect.Proxy
                        .newProxyInstance(TaskMonitor.class.getClassLoader(),
                            new Class[]{TaskMonitor.class},(proxy,method,args2)-> {
                            if(method.getName().equals("checkCancelled")) {
                                if(checks.incrementAndGet()>35)
                                    throw new CancelledException();
                                return null;
                            }
                            return method.invoke(TaskMonitor.DUMMY,args2);
                        });
                    boolean cancelled=false;
                    try {
                        new HardwareInventoryService().scan(
                            full,true,cancelling,started);
                    } catch(CancelledException expected) {cancelled=true;}
                    check(cancelled && checks.get()>35,
                        "Real analysis did not cancel during traversal");
                    check(!ghidrassist.hardware.HardwareEvidenceCache.hasEvidence(full),
                        "Cancelled analysis published incomplete RAG evidence");
                    check(full.getModificationNumber()==rev,
                        "Cancelled read-only analysis modified Program");
                    var first=HardwareFlowStageCache.loadOrAnalyze(
                        full,started,TaskMonitor.DUMMY);
                    var retry=HardwareFlowStageCache.loadOrAnalyze(
                        full,started,TaskMonitor.DUMMY);
                    check(!first.reused() && retry.reused() &&
                          first.report()==retry.report(),
                        "Cancelled stage leaked into a supposedly complete cache");
                    check(!ghidrassist.hardware.HardwareEvidenceCache.hasEvidence(full),
                        "CFG checkpoint auto-published incomplete AI context");
                    result.addProperty("cancel_real_scan_mid_traversal",true);
                    result.addProperty("cancel_incomplete_rag_not_published",true);
                    result.addProperty("cancel_clean_retry_computed",true);
                    result.addProperty("cancel_complete_stage_reused",true);
                    result.addProperty("cancel_real_program_unchanged",true);

                } else if("function-rename".equals(ga18Mode)) {
                    // Two genuine FunctionManager objects, three decoded
                    // register writes each. Collision must roll back a
                    // two-item approval batch; a later clean Apply is undoable.
                    byte[] code=java.util.HexFormat.of().parseHex(
                        "33fc387c00fffa4c33fc7c3000fffa4e" +
                        "33fc2f7f00fffa444e75");
                    int t=full.startTransaction("GA18 B function proposal fixtures");
                    try {
                        full.getMemory().setBytes(address(full,0x5a0L),code);
                        full.getMemory().setBytes(address(full,0x640L),code);
                    } finally {full.endTransaction(t,true);}
                    defineFixtureFunction(full,0x5a0L,26,"FUN_000005A0");
                    defineFixtureFunction(full,0x640L,26,"FUN_00000640");
                    var fn1=full.getFunctionManager().getFunctionAt(
                        address(full,0x5a0L));
                    var fn2=full.getFunctionManager().getFunctionAt(
                        address(full,0x640L));
                    check(fn1!=null && fn2!=null,
                        "Real Ghidra FunctionManager lost naming fixture");
                    java.util.List<ghidrassist.hardware.HardwareFunctionNamingReview.Observation>
                        observations=new java.util.ArrayList<>();
                    for(long entry2:new long[]{0x5a0L,0x640L}) {
                        var fn=full.getFunctionManager().getFunctionAt(
                            address(full,entry2));
                        String[] registers={"CSBAR0","CSOR0","CSPAR0"};
                        for(int idx=0;idx<3;idx++){
                            long pc=entry2+8L*idx;
                            check(full.getListing().getInstructionAt(
                                address(full,pc))!=null,
                                "Missing real instruction for function naming receipt");
                            observations.add(new
                                ghidrassist.hardware.HardwareFunctionNamingReview
                                    .Observation(entry2,fn.getName(),pc,
                                        registers[idx],true));
                        }
                    }
                    var proposals=ghidrassist.hardware.HardwareFunctionNamingReview
                        .propose(true,observations,List.of());
                    check(proposals.size()==2 &&
                          proposals.stream().allMatch(p->
                            p.status==ghidrassist.hardware.HardwareNamingReview
                                .Status.REVIEW_REQUIRED),
                        "Function proposal generator did not approve three real writes");
                    var first=proposals.get(0);
                    var second=proposals.get(1);
                    String firstName=fn1.getName(),secondName=fn2.getName();
                    int conflict=full.startTransaction(
                        "GA18 B create genuine user function-name collision");
                    try {
                        full.getSymbolTable().createLabel(address(full,0x680L),
                            second.proposedName,SourceType.USER_DEFINED);
                    } finally {full.endTransaction(conflict,true);}
                    check(ghidrassist.hardware.HardwareFunctionRenameService
                        .preflight(full,second)==
                        ghidrassist.hardware.HardwareFunctionRenamePolicy.Decision
                            .NAME_COLLISION,
                        "Ghidra global name collision not found in preflight");
                    boolean rolledBack=false;
                    try {
                        ghidrassist.hardware.HardwareFunctionRenameService.apply(
                            full,List.of(first,second));
                    }catch(IllegalStateException expected) {rolledBack=true;}
                    check(rolledBack &&
                          fn1.getName().equals(firstName) &&
                          fn2.getName().equals(secondName),
                        "Name collision committed a partial batch rename");
                    int remove=full.startTransaction(
                        "GA18 B remove test-only collision");
                    try {
                        check(full.getSymbolTable().getPrimarySymbol(
                            address(full,0x680L)).delete(),
                            "Failed to remove test-only collision");
                    } finally {full.endTransaction(remove,true);}
                    check(ghidrassist.hardware.HardwareFunctionRenameService
                        .preflight(full,first)==
                            ghidrassist.hardware.HardwareFunctionRenamePolicy
                                .Decision.READY &&
                          ghidrassist.hardware.HardwareFunctionRenameService
                        .preflight(full,second)==
                            ghidrassist.hardware.HardwareFunctionRenamePolicy
                                .Decision.READY,
                        "Clean real-Ghidra naming preflight was not READY");
                    var renamed=ghidrassist.hardware.HardwareFunctionRenameService
                        .apply(full,List.of(first,second));
                    check(renamed.renamed()==2 &&
                          fn1.getName().equals(first.proposedName) &&
                          fn2.getName().equals(second.proposedName),
                        "Actual Ghidra USER_DEFINED function rename failed");
                    check(full.canUndo(),"Real Ghidra Undo unavailable after renames");
                    full.undo();
                    check(fn1.getName().equals(firstName) &&
                          fn2.getName().equals(secondName),
                        "Ghidra native Undo failed to restore both function names");
                    result.addProperty("rename_real_functions_and_collision",true);
                    result.addProperty("rename_atomic_rollback",true);
                    result.addProperty("rename_transactional_two_function_apply",true);
                    result.addProperty("rename_native_undo_restored",true);
                } else if("apply-preserve".equals(ga18Mode)) {
                    // Two disposable MC68332 MM1 blocks: preserve a user
                    // symbol, existing Word data and real CPU32 code while
                    // applying ONLY an explicitly approved register row.
                    var items=ghidrassist.hardware.HardwareApplyPlan
                        .mc68332Mm1Candidates(0);
                    var simcrItem=items.stream().filter(p->p.name.equals("SIMCR"))
                        .findFirst().orElseThrow();
                    var syncrItem=items.stream().filter(p->p.name.equals("SYNCR"))
                        .findFirst().orElseThrow();
                    var qsmcrItem=items.stream().filter(p->p.name.equals("QSMCR"))
                        .findFirst().orElseThrow();
                    int tx2=full.startTransaction("GA18 B test-only MM1 mapped memory");
                    try {
                        full.getMemory().createInitializedBlock("GA18_USER_SIM",
                            address(full,0xfffa00L),128,(byte)0,
                            TaskMonitor.DUMMY,false);
                        full.getMemory().createInitializedBlock("GA18_USER_QSM",
                            address(full,0xfffc00L),128,(byte)0,
                            TaskMonitor.DUMMY,false);
                        full.getMemory().setBytes(address(full,0xfffc00L),
                            java.util.HexFormat.of().parseHex("4e75"));
                        full.getSymbolTable().createLabel(
                            address(full,0xfffa00L),"USER_SIMCR_KEEP",
                            SourceType.USER_DEFINED);
                        full.getListing().createData(address(full,0xfffa04L),
                            ghidra.program.model.data.WordDataType.dataType);
                        check(new DisassembleCommand(address(full,0xfffc00L),
                            null,false).applyTo(full,TaskMonitor.DUMMY),
                            "Actual CPU32 QSM source code fixture did not disassemble");
                    } finally {full.endTransaction(tx2,true);}
                    var wordBefore=full.getListing().getDataAt(
                        address(full,0xfffa04L)).getDataType().getName();
                    check(ghidrassist.hardware.HardwareApplyService.preflight(
                            full,simcrItem,items).state==
                          ghidrassist.hardware.HardwareApplyService.State.BLOCKED,
                        "Real user-defined SIMCR label was not guarded");
                    check(ghidrassist.hardware.HardwareApplyService.preflight(
                            full,syncrItem,items).state==
                          ghidrassist.hardware.HardwareApplyService.State.UPGRADE,
                        "Existing typed Word should allow label-only upgrade");
                    check(full.getListing().getInstructionAt(
                        address(full,0xfffc00L))!=null,
                        "Real CPU32 QSM instruction missing");
                    var outcome=ghidrassist.hardware.HardwareApplyService.apply(
                        full,List.of(simcrItem,syncrItem,qsmcrItem));
                    check(outcome.changed==1 &&
                          "USER_SIMCR_KEEP".equals(full.getSymbolTable()
                            .getPrimarySymbol(address(full,0xfffa00L)).getName()) &&
                          "SYNCR".equals(full.getSymbolTable()
                            .getPrimarySymbol(address(full,0xfffa04L)).getName()) &&
                          wordBefore.equals(full.getListing().getDataAt(
                            address(full,0xfffa04L)).getDataType().getName()) &&
                          full.getListing().getInstructionAt(
                            address(full,0xfffc00L))!=null,
                        "Unsafe Apply changed existing label, type, or code");
                    full.undo();
                    check(full.getSymbolTable().getPrimarySymbol(
                              address(full,0xfffa04L))==null &&
                          "USER_SIMCR_KEEP".equals(full.getSymbolTable()
                            .getPrimarySymbol(address(full,0xfffa00L)).getName()) &&
                          wordBefore.equals(full.getListing().getDataAt(
                            address(full,0xfffa04L)).getDataType().getName()),
                        "Ghidra Undo failed to retain pre-existing user content");
                    result.addProperty("apply_real_label_protected",true);
                    result.addProperty("apply_real_typed_data_preserved",true);
                    result.addProperty("apply_existing_code_protected",true);
                    result.addProperty("apply_native_undo_restored",true);
                } else if("provenance-csv".equals(ga18Mode)) {
                    // SourceType is a real Ghidra symbol classification,
                    // never evidence of a human, model or importer identity.
                    int tx2=full.startTransaction(
                        "GA18 B test-only SourceType labels");
                    try {
                        full.getSymbolTable().createLabel(
                            address(full,0x680L),"USER_ORIGIN_UNKNOWN",
                            SourceType.USER_DEFINED);
                        full.getSymbolTable().createLabel(
                            address(full,0x682L),"ANALYSIS_ORIGIN_UNKNOWN",
                            SourceType.ANALYSIS);
                    } finally {full.endTransaction(tx2,true);}
                    var userSym=full.getSymbolTable().getPrimarySymbol(
                        address(full,0x680L));
                    var analyzerSym=full.getSymbolTable().getPrimarySymbol(
                        address(full,0x682L));
                    check(userSym!=null && analyzerSym!=null &&
                          userSym.getSource()==SourceType.USER_DEFINED &&
                          analyzerSym.getSource()==SourceType.ANALYSIS,
                        "Actual Ghidra source classifications not observed");
                    long rev=full.getModificationNumber();
                    var rows=List.of(
                        new ghidrassist.hardware.HardwareChangeProvenance
                            .ReviewRow("REGISTER","0x00000680","=HYPERLINK(1)",
                                userSym.getName(),userSym.getSource().name(),
                                "BLOCKED",false," \u200b=2+2"),
                        new ghidrassist.hardware.HardwareChangeProvenance
                            .ReviewRow("REGISTER","0x00000682","SAFE_CANDIDATE",
                                analyzerSym.getName(),
                                analyzerSym.getSource().name(),
                                "MANUAL_REVIEW",false,"SOURCE UNKNOWN"));
                    String csv=ghidrassist.hardware.HardwareChangeProvenance
                        .csv(rows);
                    check(csv.contains("USER_DEFINED") &&
                          csv.contains("ANALYSIS") &&
                          csv.contains("author UNKNOWN") &&
                          csv.contains("analyzer/tool identity UNKNOWN") &&
                          csv.contains("'=HYPERLINK(1)") &&
                          csv.contains("LOCAL_READ_ONLY_CSV")==false &&
                          full.getModificationNumber()==rev,
                        "CSV lost genuine SourceType or failed formula sanitization");
                    result.addProperty("provenance_actual_source_types",true);
                    result.addProperty("provenance_authorship_not_invented",true);
                    result.addProperty("provenance_csv_formula_escaped",true);
                    result.addProperty("provenance_csv_read_only",true);
                    Files.writeString(out.resolve("ga18-provenance-source.csv"),csv);
                } else if("movec-vbr".equals(ga18Mode)) {
                    // MOVE.L #0x400,D0; MOVEC D0,VBR; RTS. Static Ghidra
                    // decode does not prove any MCU-executed VBR write.
                    int t=full.startTransaction("GA18 B test-only MOVEC VBR");
                    try {
                        full.getMemory().setBytes(address(full,0x5a0L),
                            java.util.HexFormat.of().parseHex(
                                "203c000004004e7b08014e75"));
                    } finally {full.endTransaction(t,true);}
                    defineFixtureFunction(full,0x5a0L,12,"fixture_movec_vbr");
                    var movec=full.getListing().getInstructionAt(
                        address(full,0x5a6L));
                    check(movec!=null &&
                          movec.getMnemonicString().toUpperCase(Locale.ROOT)
                            .startsWith("MOVEC") &&
                          movec.toString().toUpperCase(Locale.ROOT)
                            .contains("VBR"),
                        "Real Ghidra CPU32 failed to decode MOVEC D0,VBR");
                    long rev=full.getModificationNumber();
                    var cfg=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(cfg.markdown.contains("VBR") &&
                          cfg.markdown.contains("runtime VBR UNKNOWN"),
                        "MOVEC source was presented as confirmed active VBR");
                    var vector=GhidraInterruptVectorService.analyze(
                        full,TaskMonitor.DUMMY);
                    expectUncertain(vector);
                    check(full.getModificationNumber()==rev,
                        "Static MOVEC/VBR scan edited Ghidra Program");
                    result.addProperty("movec_actual_cpu32_decoded",true);
                    result.addProperty("movec_source_vbr_recognized",true);
                    result.addProperty("movec_runtime_vbr_unknown",true);
                    result.addProperty("movec_vector_scan_read_only",true);
                } else if("revision".equals(ga18Mode)) {
                    // A real Ghidra transaction changes DomainObject revision;
                    // Undo/Redo must never reinstate obsolete CFG stage evidence.
                    Address scratch=address(full,0x560L);
                    byte initial=full.getMemory().getByte(scratch);
                    String importedSha=full.getExecutableSHA256();
                    HardwareFlowStageCache.clear(full);
                    HardwareAnalysisRevision initialRevision=
                        HardwareAnalysisRevision.capture(
                            full,hwBefore,full.getLanguageID().toString(),
                            importedSha,true);
                    var baseline=HardwareFlowStageCache.loadOrAnalyze(
                        full,initialRevision,TaskMonitor.DUMMY);
                    check(!baseline.reused(),"Revision baseline must compute");
                    check(HardwareFlowStageCache.loadOrAnalyze(
                            full,initialRevision,TaskMonitor.DUMMY).reused(),
                        "Revision baseline must reuse exact stage");
                    int editTx=full.startTransaction(
                        "GA18 test-only raw byte revision edit");
                    boolean editCommit=false;
                    try {
                        full.getMemory().setByte(scratch,(byte)(initial^0x7f));
                        editCommit=true;
                    } finally { full.endTransaction(editTx,editCommit); }
                    long edited=full.getModificationNumber();
                    check(edited!=hwBefore &&
                          full.getMemory().getByte(scratch)!=(byte)initial,
                        "Real Ghidra test edit did not change program revision");
                    check(Objects.equals(importedSha,full.getExecutableSHA256()),
                        "Original import SHA is metadata, not mutable memory hash");
                    try {
                        HardwareFlowStageCache.loadOrAnalyze(
                            full,initialRevision,TaskMonitor.DUMMY);
                        throw new AssertionError(
                            "Stale captured revision accepted after real edit");
                    } catch(CancelledException expected) {
                        // Fail closed before any stale stage is published.
                    }
                    HardwareAnalysisRevision editRevision=
                        HardwareAnalysisRevision.capture(
                            full,edited,full.getLanguageID().toString(),
                            importedSha,true);
                    var changed=HardwareFlowStageCache.loadOrAnalyze(
                        full,editRevision,TaskMonitor.DUMMY);
                    check(!changed.reused() && changed.report()!=baseline.report(),
                        "Changed real Ghidra Program reused stale CFG stage");
                    check(HardwareFlowStageCache.loadOrAnalyze(
                            full,editRevision,TaskMonitor.DUMMY).reused(),
                        "Edited stable revision should reuse complete stage");
                    check(full.canUndo(),
                        "Ghidra test Program has no native Undo after edit");
                    full.undo();
                    long undone=full.getModificationNumber();
                    check(undone!=edited &&
                          full.getMemory().getByte(scratch)==initial,
                        "Native Ghidra Undo did not restore test byte/revision");
                    try {
                        HardwareFlowStageCache.loadOrAnalyze(
                            full,editRevision,TaskMonitor.DUMMY);
                        throw new AssertionError(
                            "Cached edited stage survived native Ghidra Undo");
                    } catch(CancelledException expected) {
                        // Expected stale-revision rejection.
                    }
                    HardwareAnalysisRevision undoRevision=
                        HardwareAnalysisRevision.capture(
                            full,undone,full.getLanguageID().toString(),
                            importedSha,true);
                    var afterUndo=HardwareFlowStageCache.loadOrAnalyze(
                        full,undoRevision,TaskMonitor.DUMMY);
                    check(!afterUndo.reused() &&
                          afterUndo.report()!=changed.report(),
                        "Undo must recompute stage despite restored byte contents");
                    check(full.canRedo(),"Ghidra test Program has no native Redo");
                    full.redo();
                    long redone=full.getModificationNumber();
                    check(redone!=undone &&
                          full.getMemory().getByte(scratch)!=(byte)initial,
                        "Ghidra Redo failed to reinstate test edit and new revision");
                    try {
                        HardwareFlowStageCache.loadOrAnalyze(
                            full,undoRevision,TaskMonitor.DUMMY);
                        throw new AssertionError(
                            "Cached Undo stage survived native Ghidra Redo");
                    } catch(CancelledException expected) {
                        // Expected stale-revision rejection.
                    }
                    HardwareAnalysisRevision redoRevision=
                        HardwareAnalysisRevision.capture(
                            full,redone,full.getLanguageID().toString(),
                            importedSha,true);
                    var afterRedo=HardwareFlowStageCache.loadOrAnalyze(
                        full,redoRevision,TaskMonitor.DUMMY);
                    check(!afterRedo.reused() &&
                          afterRedo.report()!=afterUndo.report(),
                        "Redo must recompute completed stage for exact input");
                    check(HardwareFlowStageCache.loadOrAnalyze(
                            full,redoRevision,TaskMonitor.DUMMY).reused(),
                        "Current redo revision must reuse stage on retry");
                    // Leave this disposable project as originally imported,
                    // without altering any external project/firmware.
                    full.undo();
                    check(full.getMemory().getByte(scratch)==initial,
                        "Final native Undo must restore initial test bytes");
                    result.addProperty("revision_real_edit_invalidated",true);
                    result.addProperty("revision_stale_capture_rejected",true);
                    result.addProperty("revision_undo_invalidated",true);
                    result.addProperty("revision_redo_invalidated",true);
                    result.addProperty("revision_original_bytes_restored",true);
                    result.addProperty("revision_import_sha_stable",true);
                } else if("startup".equals(ga18Mode)) {
                    // These sites are decoded by Ghidra, not model-only nodes.
                    // The first SITE in a FUNCTION is not first hardware write.
                    GhidraHardwareFlowService.Report cfg=
                        new GhidraHardwareFlowService().analyze(
                            full,TaskMonitor.DUMMY,true);
                    check(cfg.rawCfgMmioSites.stream().anyMatch(s->
                            "SIMCR".equals(s.register()) &&
                            s.pc()==0x500L && s.widthBits()==16 &&
                            Integer.valueOf(0x40ca).equals(s.literal())),
                        "CFG/P-code missed real decoded 16-bit SIMCR literal");
                    check(cfg.markdown.contains(
                            "Possible first SIMCR source sites within individual functions") &&
                          cfg.markdown.contains("PC 0x00000500 -> word 0x40CA") &&
                          cfg.markdown.contains("NOT") &&
                          cfg.markdown.contains("MM write-once"),
                        "Potential local-first path incorrectly became runtime order");
                    HardwareInventoryService.Report inventory=
                        new HardwareInventoryService().scan(
                            full,true,TaskMonitor.DUMMY);
                    check(inventory.overviewMarkdown.contains(
                            "Source-reconciled Listing + CFG/P-code candidate sites:") &&
                          inventory.markdown.contains(
                            "Unified startup write evidence") &&
                          inventory.csbarReview.candidates().isEmpty(),
                        "Real inventory did not reconcile CFG/Listing conservatively");
                    check(full.getModificationNumber()==hwBefore,
                        "Read-only startup scan changed real Ghidra Program");
                    result.addProperty("simcr_real_listing_pcode_verified",true);
                    result.addProperty("simcr_local_first_only_verified",true);
                    result.addProperty("listing_cfg_reconciliation_verified",true);
                    Files.writeString(out.resolve("ga18-startup.md"),cfg.markdown);
                } else if("csbar".equals(ga18Mode)) {
                    // Three independent, real disassembled CPU32 functions.
                    // No static source address order establishes CS activation.
                    defineFixtureFunction(full,0x520L,10,"synthetic_csbar0_a");
                    long beforeOne=full.getModificationNumber();
                    HardwareInventoryService service=new HardwareInventoryService();
                    var one=service.scan(full,true,TaskMonitor.DUMMY);
                    check(one.csbarReview.candidates().stream().anyMatch(c->
                            "CSBAR0".equals(c.register()) && c.word()==0x387c),
                        "One complete real CSBAR source should be manual proposal only");
                    check(full.getModificationNumber()==beforeOne,
                        "CSBAR candidate scan must remain read-only");
                    defineFixtureFunction(full,0x530L,10,"synthetic_csbar0_conflict");
                    long beforeTwo=full.getModificationNumber();
                    var conflict=service.scan(full,true,TaskMonitor.DUMMY);
                    check(conflict.csbarReview.candidates().stream().noneMatch(c->
                            "CSBAR0".equals(c.register())),
                        "Conflicting real CSBAR literal must block its window proposal");
                    check(full.getModificationNumber()==beforeTwo,
                        "CSBAR conflict scan modified the Program");
                    defineFixtureFunction(full,0x540L,4,"synthetic_unknown_address_store");
                    long beforeAlias=full.getModificationNumber();
                    var alias=service.scan(full,true,TaskMonitor.DUMMY);
                    check(alias.csbarReview.unresolvedAliasWrites()>0 &&
                          alias.csbarReview.candidates().isEmpty(),
                        "Unknown real P-code STORE may alias ANY CSBAR");
                    check(alias.csbarReview.summary().contains(
                            "MM latch and actual chip-select assertion UNKNOWN") &&
                          full.getModificationNumber()==beforeAlias,
                        "Source-only CSBAR Review must not infer active hardware or edit Ghidra");
                    result.addProperty("csbar_real_literal_proposal_manual_only",true);
                    result.addProperty("csbar_real_conflicting_literals_blocked",true);
                    result.addProperty("unknown_store_all_cs_windows_blocked",true);
                    Files.writeString(out.resolve("ga18-csbar-conflict.md"),
                                      conflict.markdown);
                    Files.writeString(out.resolve("ga18-csbar-alias.md"),
                                      alias.markdown);
                }
                result.addProperty("read_only_analysis_verified",true);
                result.addProperty("ga18_mode",ga18Mode);
            }
            result.addProperty("state","PASSED_SYNTHETIC_REAL_GHIDRA_HEADLESS");
            result.addProperty("full_program_vectors",254);
            result.addProperty("truncated_image_unreadable",244);
            result.addProperty("function_entry_and_body_verified",true);
            result.addProperty("production_flow_integration_verified",true);
            result.addProperty("read_only_analyze_verified",true);
            result.addProperty("no_runtime_vbr_isr_claim",true);
            Files.writeString(out.resolve("report-full.md"),main);
            Files.writeString(out.resolve("report-short.md"),shortReport);
        } finally {
            if(full!=null)full.release(consumer);
            if(shortImage!=null)shortImage.release(consumer);
            project.close();
            Files.writeString(out.resolve("result.json"),JSON.toJson(result)+"\n");
        }
    }
}
