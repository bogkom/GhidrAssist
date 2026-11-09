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
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;
import ghidrassist.hardware.GhidraInterruptVectorService;
import ghidrassist.hardware.GhidraHardwareFlowService;
import ghidrassist.hardware.HardwareIndexedAddress;
import ghidrassist.hardware.HardwareInventoryService;
import ghidrassist.hardware.HardwareFlowStageCache;
import ghidrassist.hardware.HardwareAnalysisRevision;
import ghidrassist.hardware.HardwareProfiles;
import ghidrassist.hardware.HardwareBitfieldSourceLedger;
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
            "simcr-partial","vector-edit-undo","reset-interior","cache-program-isolation",
            "generic-profile","trambar-source","csbar-mm0-reject",
            "mmio-read-reference","csbar-csor-conditional",
            "simcr-mm0-literal","trambar-unknown","csor-alternatives",
            "branch-simcr","call-barrier","leaf-return","call-context","joint-source","two-hop","two-hop-indexed","two-hop-indexed-wrap","indirect-adjacent","indirect-bounded","indirect-reset-xref","branch-leaf","branch-cache","cancel-incomplete",
            "function-stage-resume","function-rename","scoped-variable","agentic-evidence","receipt-restart-write",
            "receipt-restart-read","apply-preserve","provenance-csv",
            "movec-vbr","vbr-relocation").contains(ga18Mode),
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
            // The second JVM of the GA-13 persistence regression opens
            // the SAME saved synthetic project. Do not create a duplicate
            // function or modify its database before checking the receipt.
            if("receipt-restart-read".equals(ga18Mode)) {
                Function existing=full.getFunctionManager().getFunctionAt(entry);
                check(existing!=null &&
                    "synthetic_vector_handler".equals(existing.getName()),
                    "Saved Ghidra vector fixture not visible after JVM restart");
            } else {
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
            }
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
                if("receipt-restart-read".equals(ga18Mode)) {
                    // Phase #1 saved this exact function. Reopening the
                    // same Ghidra Program MUST NOT create another function
                    // or run any write transaction before verifying GA-13.
                    Function mmioFunction=full.getFunctionManager()
                        .getFunctionAt(mmio);
                    check(mmioFunction!=null &&
                          "synthetic_simcr_write".equals(mmioFunction.getName()),
                        "Second JVM lost existing synthetic SIMCR function");
                } else {
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
                }
                long hwBefore=full.getModificationNumber();
                if("reset-interior".equals(ga18Mode)){
                    // Real synthetic CPU32: JSR at 0x620 and RTS at 0x626
                    // belong to ONE function. RESET at 0x626 must NOT
                    // "inherit" the earlier JSR to SIMCR source at 0x500.
                    int fixtureTx=full.startTransaction(
                        "GA01 isolated RESET/CALL prefix fixture");
                    try {
                        full.getMemory().setBytes(address(full,0x620L),
                            java.util.HexFormat.of().parseHex(
                                "4eb9000005004e75"));
                    } finally {full.endTransaction(fixtureTx,true);}
                    defineFixtureFunction(full,0x620L,8,
                        "ga01_reset_prefix_jsr_then_rts");
                    var callBeforeReset=full.getListing().getInstructionAt(
                        address(full,0x620L));
                    check(callBeforeReset!=null &&
                        callBeforeReset.getFlowType().isCall() &&
                        callBeforeReset.getFlows().length==1 &&
                        callBeforeReset.getFlows()[0].equals(
                            address(full,0x500L)),
                        "Real decoded CPU32 JSR before vector PC not proven");
                    check(full.getFunctionManager().getFunctionContaining(
                        address(full,0x626L))!=null &&
                        full.getFunctionManager().getFunctionAt(
                            address(full,0x626L))==null,
                        "Real Ghidra function body is not an exact RESET entry");
                    int exactTx=full.startTransaction(
                        "GA01 test-only exact RESET entry vector");
                    try {
                        full.getMemory().setBytes(address(full,4L),
                            java.util.HexFormat.of().parseHex("00000620"));
                    } finally {full.endTransaction(exactTx,true);}
                    long exactRevision=full.getModificationNumber();
                    var exactReport=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(exactReport.resetCandidateRecognized &&
                        exactReport.resetCandidateFunctions.contains(0x620L) &&
                        exactReport.resetCandidateFunctions.contains(0x500L) &&
                        exactReport.markdown.contains(
                            "candidate chain 0x00000620 -> 0x00000500") &&
                        full.getModificationNumber()==exactRevision,
                        "Exact Ghidra RESET entry must retain direct JSR "+
                        "to synthetic MMIO leaf as static source evidence");
                    int interiorTx=full.startTransaction(
                        "GA01 test-only interior RESET vector");
                    try {
                        full.getMemory().setBytes(address(full,4L),
                            java.util.HexFormat.of().parseHex("00000626"));
                    } finally {full.endTransaction(interiorTx,true);}
                    long interiorRevision=full.getModificationNumber();
                    var interiorReport=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(!interiorReport.resetCandidateRecognized &&
                        interiorReport.resetGraphIncomplete &&
                        interiorReport.resetCandidateFunctions.isEmpty() &&
                        interiorReport.markdown.contains(
                            "UNKNOWN RESET ROOT — INTERIOR FUNCTION POINTER") &&
                        interiorReport.markdown.contains("RESET_ROOT_UNKNOWN") &&
                        !interiorReport.markdown.contains(
                            "candidate chain 0x00000620 -> 0x00000500") &&
                        full.getModificationNumber()==interiorRevision,
                        "Interior RESET source must NOT turn preceding CALL "+
                        "into reachable MMIO/ISR evidence");
                    var replay=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    // Process-local stage counters may change on replay:
                    // compare persistent RESET relations, not whole Markdown.
                    check(replay.resetCandidateFunctions.isEmpty() &&
                        !replay.resetCandidateRecognized &&
                        replay.resetGraphIncomplete &&
                        replay.markdown.contains(
                            "UNKNOWN RESET ROOT — INTERIOR FUNCTION POINTER") &&
                        replay.markdown.contains("RESET_ROOT_UNKNOWN") &&
                        !replay.markdown.contains(
                            "candidate chain 0x00000620 -> 0x00000500") &&
                        full.getModificationNumber()==interiorRevision,
                        "Same-revision replay cannot restore stale exact-entry "+
                        "RESET graph from previous source-vector revision");
                    result.addProperty("reset_exact_entry_real_jsr_visible",true);
                    result.addProperty("reset_interior_real_function_not_entry",true);
                    result.addProperty("reset_interior_no_false_mmio_reachability",true);
                    result.addProperty("reset_interior_revision_cache_conservative",true);
                    result.addProperty("reset_interior_read_only",true);
                } else if("overview".equals(ga18Mode)){
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
                    // Ghidra's headless DisassembleCommand does not always
                    // follow both targets of a conditionally-entered stub.
                    // Independently request the second code-flow target.
                    int branches=full.startTransaction(
                        "GA18 A decode conditional second target");
                    try {
                        check(new DisassembleCommand(address(full,0x5acL),
                            null,false).applyTo(full,TaskMonitor.DUMMY),
                            "Ghidra failed to decode synthetic second branch");
                    } finally {full.endTransaction(branches,true);}
                    long rev=full.getModificationNumber();
                    var cfg=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(cfg.rawCfgMmioSites.stream().anyMatch(site->
                            site.pc()==0x5a2L && "SIMCR".equals(site.register()) &&
                            Integer.valueOf(0x40ca).equals(site.literal())) &&
                          cfg.rawCfgMmioSites.stream().anyMatch(site->
                            site.pc()==0x5acL && "SIMCR".equals(site.register()) &&
                            Integer.valueOf(0x4848).equals(site.literal())),
                        "Real conditional CPU32 SIMCR branches lost literal evidence; raw="+
                            cfg.rawCfgMmioSites.stream().filter(site->
                                site.function()==0x5a0L).toList()+
                            "; Listing="+full.getListing().getInstructionAt(
                                address(full,0x5a2L))+"/"+
                                full.getListing().getInstructionAt(
                                    address(full,0x5acL)));
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
                } else if("branch-leaf".equals(ga18Mode) ||
                        "branch-cache".equals(ga18Mode)) {
                    // Real CPU32 conditional BNE and BRA; both reachable paths
                    // agree on A0 in the positive callee. A negative control
                    // returns conflicting A0 values and must remain unknown.
                    int branchTx=full.startTransaction("GA02 synthetic branch-convergent leaf");
                    try {
                        full.getMemory().setBytes(address(full,0x760L),
                            java.util.HexFormat.of().parseHex(
                                "203c000040ca6608207c00fffa006006207c00fffa004e75"));
                        full.getMemory().setBytes(address(full,0x7a0L),
                            java.util.HexFormat.of().parseHex(
                                "203c000040ca6608207c00fffa006006207c007ffa004e75"));
                        full.getMemory().setBytes(address(full,0x720L),
                            java.util.HexFormat.of().parseHex(
                                "4eb90000076030804e75"));
                        full.getMemory().setBytes(address(full,0x7d0L),
                            java.util.HexFormat.of().parseHex(
                                "4eb9000007a030804e75"));
                    } finally { full.endTransaction(branchTx,true); }
                    // Ensure the alternative branch targets are also decoded
                    // in the isolated fixture. The initial disassembler pass
                    // may stop at the unconditional BRA on the fallthrough.
                    int branchDecodeTx=full.startTransaction("GA02 synthetic branch arms");
                    try{
                        check(new DisassembleCommand(address(full,0x770L),null,false)
                            .applyTo(full,TaskMonitor.DUMMY),
                            "Ghidra failed positive alternative branch arm");
                        check(new DisassembleCommand(address(full,0x7b0L),null,false)
                            .applyTo(full,TaskMonitor.DUMMY),
                            "Ghidra failed negative alternative branch arm");
                    }finally{full.endTransaction(branchDecodeTx,true);}
                    defineFixtureFunction(full,0x760L,24,"fixture_branch_two_agreeing_returns");
                    defineFixtureFunction(full,0x7a0L,24,"fixture_branch_disagreeing_return");
                    defineFixtureFunction(full,0x720L,10,"fixture_branch_positive_caller");
                    defineFixtureFunction(full,0x7d0L,10,"fixture_branch_negative_caller");
                    long branchRevisionBefore=full.getModificationNumber();
                    var report=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    var leafMethod=GhidraHardwareFlowService.class.getDeclaredMethod(
                        "verifiedLeafReturn",Program.class,Function.class,TaskMonitor.class);
                    leafMethod.setAccessible(true);
                    var decodedLeaf=leafMethod.invoke(null,full,
                        full.getFunctionManager().getFunctionAt(address(full,0x760L)),
                        TaskMonitor.DUMMY);
                    StringBuilder branchDiag=new StringBuilder();
                    var dec=full.getListing().getInstructions(
                        full.getFunctionManager().getFunctionAt(
                            address(full,0x760L)).getBody(),true);
                    while(dec.hasNext()){
                        var insn=dec.next();
                        branchDiag.append("pc=").append(insn.getAddress())
                            .append(" mnemonic=").append(insn.getMnemonicString())
                            .append(" flows=").append(java.util.Arrays.toString(insn.getFlows()))
                            .append(" fall=").append(insn.getFallThrough()).append("; ");
                    }
                    System.out.println("GA02 BRANCH DIAG returns="+decodedLeaf+
                        " instructions="+branchDiag+" mmio="+
                        report.rawCfgMmioSites.stream()
                            .filter(site->site.pc()>=0x720L && site.pc()<0x7f0L)
                            .map(site->Long.toHexString(site.pc())+":"+site.register()+
                                ":"+site.literal()).toList());
                    check(report.rawCfgMmioSites.stream().anyMatch(site->
                            site.pc()==0x726L && site.address()==0xfffa00L &&
                            "SIMCR".equals(site.register()) &&
                            Integer.valueOf(0x40ca).equals(site.literal()) &&
                            site.unknownCall()),
                        "Convergent branch did not prove caller SIMCR registers");
                    check(report.rawCfgMmioSites.stream().anyMatch(site->
                            site.pc()==0x7d6L &&
                            "UNRESOLVED_ALIAS".equals(site.register()) &&
                            site.unknownCall()),
                        "Disagreeing branch invented fixed SIMCR address");
                    check(full.getModificationNumber()==branchRevisionBefore,
                        "Branch static analysis altered Ghidra Program");
                    var generic=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,false);
                    check(generic.rawCfgMmioSites.stream().noneMatch(site->
                            site.pc()==0x726L &&
                            "SIMCR".equals(site.register())),
                        "Generic CPU32 inherited MC68332 register evidence");
                    if("branch-cache".equals(ga18Mode)){
                        HardwareFlowStageCache.clear(full);
                        long revision=full.getModificationNumber();
                        var stageRevision=HardwareAnalysisRevision.capture(
                            full,revision,full.getLanguageID().toString(),
                            full.getExecutableSHA256(),true);
                        var cold=HardwareFlowStageCache.loadOrAnalyze(
                            full,stageRevision,TaskMonitor.DUMMY);
                        check(!cold.reused() &&
                            cold.report().rawCfgMmioSites.stream().anyMatch(site->
                                site.pc()==0x726L &&
                                "SIMCR".equals(site.register()) &&
                                Integer.valueOf(0x40ca).equals(site.literal()) &&
                                site.unknownCall()),
                            "Combined GA-02/03+GA-12 cache lost proven branch CALL source");
                        check(GhidraHardwareFlowService.checkpointedFunctionStages(full)>0,
                            "GA-12 did not checkpoint completed CFG functions");
                        var reused=HardwareFlowStageCache.loadOrAnalyze(
                            full,stageRevision,TaskMonitor.DUMMY);
                        check(reused.reused() &&
                            reused.report().rawCfgMmioSites.equals(
                                cold.report().rawCfgMmioSites),
                            "GA-12 whole-stage reuse changed branch CALL source evidence");
                        HardwareFlowStageCache.clear(full);
                        var afterClear=HardwareFlowStageCache.loadOrAnalyze(
                            full,stageRevision,TaskMonitor.DUMMY);
                        check(!afterClear.reused() &&
                            afterClear.report().rawCfgMmioSites.equals(
                                cold.report().rawCfgMmioSites) &&
                            full.getModificationNumber()==revision,
                            "Explicit cache invalidation changed source proof or Program");
                        result.addProperty("cross_track_real_branch_source_proven",true);
                        result.addProperty("cross_track_real_function_checkpoints",true);
                        result.addProperty("cross_track_real_completed_stage_reused",true);
                        result.addProperty("cross_track_real_invalidate_recomputed",true);
                        result.addProperty("cross_track_real_program_read_only",true);
                    }
                    result.addProperty("branch_leaf_real_convergent_proven",true);
                    result.addProperty("branch_leaf_disagreeing_address_unknown",true);
                    result.addProperty("branch_leaf_call_history_uncertain",true);
                    result.addProperty("branch_leaf_generic_cpu32_conservative",true);
                    result.addProperty("branch_leaf_program_read_only",true);
                } else if("two-hop".equals(ga18Mode)) {
                    // Real CPU32 Listing: two independent outer JSR sources,
                    // one fully decoded bridge with exactly ONE nested JSR,
                    // and a leaf indirect STORE. Only potential source
                    // provenance, never an executed call or hardware state.
                    int txTwoHop=full.startTransaction(
                        "GA02 isolated two-hop direct JSR fixture");
                    try{
                        full.getMemory().setBytes(address(full,0x700L),
                            java.util.HexFormat.of().parseHex("32804e75"));
                        full.getMemory().setBytes(address(full,0x640L),
                            java.util.HexFormat.of().parseHex(
                                "22484eb9000007004e75"));
                        full.getMemory().setBytes(address(full,0x600L),
                            java.util.HexFormat.of().parseHex(
                                "207c00fffa00203c000040ca4eb9000006404e75"));
                        full.getMemory().setBytes(address(full,0x680L),
                            java.util.HexFormat.of().parseHex(
                                "207c00fffa68203c000048484eb9000006404e75"));
                        full.getMemory().setBytes(address(full,0x6a0L),
                            java.util.HexFormat.of().parseHex(
                                "203c000040ca4eb9000006404e75"));
                    }finally{full.endTransaction(txTwoHop,true);}
                    defineFixtureFunction(full,0x700L,4,
                        "ga02_twohop_final_move_d0_to_a1");
                    defineFixtureFunction(full,0x640L,10,
                        "ga02_twohop_bridge_movea_and_jsr");
                    defineFixtureFunction(full,0x600L,20,
                        "ga02_twohop_simcr_caller");
                    defineFixtureFunction(full,0x680L,20,
                        "ga02_twohop_cs_caller");
                    defineFixtureFunction(full,0x6a0L,14,
                        "ga02_twohop_unknown_a0_caller");
                    var nested=full.getListing().getInstructionAt(
                        address(full,0x642L));
                    check(nested!=null && nested.getFlowType().isCall() &&
                        nested.getFlows().length==1 &&
                        nested.getFlows()[0].equals(address(full,0x700L)),
                        "Real Ghidra CPU32 did not decode bridge JSR");
                    var copy=full.getListing().getInstructionAt(
                        address(full,0x640L));
                    check(copy!=null && copy.getMnemonicString()
                        .toUpperCase(Locale.ROOT).startsWith("MOVEA"),
                        "Real CPU32 did not decode bridge MOVEA.L A0,A1");
                    long revision=full.getModificationNumber();
                    var report=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    String markdown=report.markdown;
                    int section=markdown.indexOf(
                        "## Bounded two-hop CALL argument/MMIO "+
                        "source candidates (GA-02/03)");
                    check(section>=0,"Two-hop source-only report not present");
                    String source=markdown.substring(section);
                    check(source.contains(
                        "| 0x00000600 | 0x0000060C | 0x00000640 | "+
                        "0x00000642 | 0x00000700 | 0x00000700 | "+
                        "0x00FFFA00 | 0x000040CA |") &&
                        source.contains(
                        "| 0x00000680 | 0x0000068C | 0x00000640 | "+
                        "0x00000642 | 0x00000700 | 0x00000700 | "+
                        "0x00FFFA68 | 0x00004848 |"),
                        "Distinct outer A/D provenance collapsed across "+
                        "one nested bridge CALL: "+
                        source.substring(0,Math.min(3800,source.length())));
                    check(source.contains("SOURCE-ONLY MAY-CANDIDATES") &&
                        source.contains("NOT EXECUTION") &&
                        source.contains("A7 is NEVER propagated") &&
                        source.contains("Review/Apply") &&
                        source.contains("unknown STORE alias: "),
                        "Two-hop candidate was promoted to actual MM "+
                        "execution or unconditional Apply evidence");
                    // Real 68000:BE:32:CPU32 source has two conflicting
                    // outer CALLs and an additional missing-A0 caller.
                    // The grouped two-hop source cannot become consensus.
                    check(source.contains(
                        "## Two-hop cross-CALL MMIO source agreement (GA-02/03)") &&
                        source.contains(
                        "SOURCE-ONLY MAY-CANDIDATES; NOT HARDWARE PROOF") &&
                        source.contains(
                        "| 0x00000640 | 0x00000700 | 0x00000700 |") &&
                        source.contains("INCOMPLETE") &&
                        !source.contains("SAMPLED_AGREEMENT"),
                        "Real nested CPU32 JSR candidates were falsely "+
                        "promoted from incomplete source inventory");
                    check(source.contains(
                        "### MC68332 register-byte coverage for two-hop CALL evidence") &&
                        source.contains("SIM.SIMCR / 0xFFFA00 / 16") &&
                        source.contains("SIM.CSBAR7 / 0xFFFA68 / 16") &&
                        source.contains("EXACT_BYTE_RANGE") &&
                        source.contains("Source-page labels are UNVERIFIED claims"),
                        "Real Ghidra two-hop MMIO sources lost selected-profile "+
                        "byte widths or promoted unverified PDF evidence");
                    check(report.rawCfgMmioSites.stream().noneMatch(s->
                        s.pc()==0x700L && s.address()==0xfffa00L),
                        "Nested callee write leaked into global Review/Apply "+
                        "eligible CFG data");
                    check(full.getModificationNumber()==revision,
                        "Two-hop source analysis modified Ghidra Program");
                    var again=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    String repeated=again.markdown.substring(
                        again.markdown.indexOf(
                            "## Bounded two-hop CALL argument/MMIO "));
                    check(repeated.equals(source) &&
                        full.getModificationNumber()==revision,
                        "GA-12 process-local replay mixed call-site contexts");
                    var generic=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,false);
                    check(generic.markdown.contains(
                        "Not evaluated: explicit MC68332 profile required") &&
                        !generic.markdown.contains(
                            "| 0x00000600 | 0x0000060C | 0x00000640 | "+
                            "0x00000642 |") &&
                        full.getModificationNumber()==revision,
                        "Generic CPU32 inherited MC68332 two-hop MMIO");
                    // GA-12: actual in-memory Ghidra Listing mutation.
                    // Decode the already validated synthetic CPU32 bridge
                    // and leaf into real production Steps, then capture
                    // genuine Program.getModificationNumber. A stale
                    // source-only two-hop observation must lose its address
                    // and *all* CALL provenance after the comment changes.
                    var realBridgeMethod=GhidraHardwareFlowService.class
                        .getDeclaredMethod("contextualBridge",Program.class,
                            Function.class,TaskMonitor.class);
                    realBridgeMethod.setAccessible(true);
                    var realLeafMethod=GhidraHardwareFlowService.class
                        .getDeclaredMethod("contextualCallee",Program.class,
                            Function.class,TaskMonitor.class);
                    realLeafMethod.setAccessible(true);
                    var realBridge=(ghidrassist.hardware.HardwareTwoHopRegisterFlow.Bridge)
                        realBridgeMethod.invoke(null,full,
                            full.getFunctionManager().getFunctionAt(
                                address(full,0x640L)),TaskMonitor.DUMMY);
                    var realLeaf=(ghidrassist.hardware.HardwareCallsiteRegisterFlow.Callee)
                        realLeafMethod.invoke(null,full,
                            full.getFunctionManager().getFunctionAt(
                                address(full,0x700L)),TaskMonitor.DUMMY);
                    check(realBridge!=null && realBridge.complete() &&
                            realLeaf!=null && realLeaf.complete() &&
                            realBridge.finalTarget()==0x700L,
                        "Actual Ghidra CPU32 direct bridge/leaf not fully decoded");
                    var realOuter=List.of(
                        new ghidrassist.hardware.HardwareCallsiteRegisterFlow.Call(
                            0x600L,0x60cL,0x640L,
                            Map.of("A0",0xfffa00L,"D0",0x40caL),false),
                        new ghidrassist.hardware.HardwareCallsiteRegisterFlow.Call(
                            0x680L,0x68cL,0x640L,
                            Map.of("A0",0xfffa68L,"D0",0x4848L),false));
                    var realTwoHop=ghidrassist.hardware.HardwareTwoHopRegisterFlow.analyze(
                        realOuter,List.of(realBridge),List.of(realLeaf),
                        Set.of(0xfffa00L,0xfffa68L),48);
                    check(realTwoHop.possibleStores()==2 &&
                            realTwoHop.rows().size()==2,
                        "Actual decoded Listing two-hop source rows incomplete");
                    var actualRevision=HardwareAnalysisRevision.capture(
                        full,full.getModificationNumber(),
                        full.getLanguage().getLanguageID().toString(),
                        full.getExecutableSHA256(),true);
                    java.util.function.Supplier<HardwareAnalysisRevision> currentRevision=
                        ()->HardwareAnalysisRevision.capture(full,
                            full.getModificationNumber(),
                            full.getLanguage().getLanguageID().toString(),
                            full.getExecutableSHA256(),true);
                    var beforeEdit=ghidrassist.hardware.HardwareTwoHopConsensus
                        .inspectScopedRevisionBound(actualRevision,currentRevision,
                            realOuter,realTwoHop,0x640L,0x700L,0x700L);
                    check(beforeEdit.state()==
                            ghidrassist.hardware.HardwareTwoHopConsensus.State.SAMPLED_DIVERGENCE &&
                            beforeEdit.provenance().size()==2,
                        "Pre-edit actual Ghidra Listing lost divergent CALL origins");
                    var editedInstruction=full.getListing().getInstructionAt(
                        address(full,0x640L));
                    byte sourceByte=full.getMemory().getByte(address(full,0x640L));
                    int editTransaction=full.startTransaction(
                        "GA12 isolated two-hop source revision invalidation");
                    try {
                        editedInstruction.setComment(
                            CodeUnit.EOL_COMMENT,
                            "GA12 disposable changed real two-hop Listing input");
                        check(full.getModificationNumber()!=
                                actualRevision.modificationNumber(),
                            "Actual Ghidra Listing edit did not advance revision");
                        var stale=ghidrassist.hardware.HardwareTwoHopConsensus
                            .inspectScopedRevisionBound(actualRevision,currentRevision,
                                realOuter,realTwoHop,0x640L,0x700L,0x700L);
                        check(stale.state()==
                                ghidrassist.hardware.HardwareTwoHopConsensus.State.STALE_REVISION &&
                                stale.provenance().isEmpty() &&
                                stale.address()==null && stale.word()==null,
                            "Edited Listing incorrectly reused stale two-hop evidence");
                        var staleMarkdown=ghidrassist.hardware.HardwareTwoHopConsensus
                            .markdown(realOuter,realTwoHop,0,16,
                                actualRevision,currentRevision);
                        check(staleMarkdown.contains("STALE_REVISION") &&
                                !staleMarkdown.contains("0x00FFFA00") &&
                                !staleMarkdown.contains("0x00FFFA68"),
                            "Edited Program leaked stale per-CALL source addresses");
                    } finally {full.endTransaction(editTransaction,false);}
                    check(full.getMemory().getByte(address(full,0x640L))==
                            sourceByte &&
                            full.getListing().getInstructionAt(
                                address(full,0x640L))!=null,
                        "Rollback damaged genuine CPU32 bridge Listing bytes");
                    var postRollbackRevision=HardwareAnalysisRevision.capture(
                        full,full.getModificationNumber(),
                        full.getLanguage().getLanguageID().toString(),
                        full.getExecutableSHA256(),true);
                    var freshPostRollback=ghidrassist.hardware.HardwareTwoHopConsensus
                        .inspectScopedRevisionBound(postRollbackRevision,
                            currentRevision,realOuter,realTwoHop,
                            0x640L,0x700L,0x700L);
                    check(freshPostRollback.state()==
                            ghidrassist.hardware.HardwareTwoHopConsensus.State.SAMPLED_DIVERGENCE,
                        "After rollback, source-only proof could not be revalidated");
                    // Real CPU32 divergent/convergent source cohort.
                    // BNE has two paths, each assigning A1=A0 before a
                    // single nested direct JSR. The final leaf contains two
                    // independently decoded STORE instructions. A second
                    // distinct bridge reaches a second distinct leaf.
                    int branchTx=full.startTransaction(
                        "GA02 isolated two bridges and multiple leaf stores");
                    try {
                        full.getMemory().setBytes(address(full,0x740L),
                            java.util.HexFormat.of().parseHex(
                                "66042248600222484eb9000007804e75"));
                        full.getMemory().setBytes(address(full,0x760L),
                            java.util.HexFormat.of().parseHex(
                                "22484eb9000007c04e75"));
                        full.getMemory().setBytes(address(full,0x780L),
                            java.util.HexFormat.of().parseHex(
                                "328032804e75"));
                        full.getMemory().setBytes(address(full,0x7c0L),
                            java.util.HexFormat.of().parseHex(
                                "32804e75"));
                        for(long callerPc:new long[]{0x900L,0x920L}) {
                            full.getMemory().setBytes(address(full,callerPc),
                                java.util.HexFormat.of().parseHex(
                                    "207c00fffa00203c000040ca"+
                                    "4eb9000007404e75"));
                        }
                        for(long callerPc:new long[]{0x940L,0x960L}) {
                            full.getMemory().setBytes(address(full,callerPc),
                                java.util.HexFormat.of().parseHex(
                                    "207c00fffa68203c00004848"+
                                    "4eb9000007604e75"));
                        }
                    }finally{full.endTransaction(branchTx,true);}
                    defineFixtureFunction(full,0x780L,6,
                        "ga02_twohop_convergent_two_store_leaf");
                    defineFixtureFunction(full,0x7c0L,4,
                        "ga02_twohop_other_leaf");
                    defineFixtureFunction(full,0x740L,16,
                        "ga02_twohop_real_branch_bridge");
                    defineFixtureFunction(full,0x760L,10,
                        "ga02_twohop_second_bridge");
                    for(long callerPc:new long[]{0x900L,0x920L,0x940L,0x960L})
                        defineFixtureFunction(full,callerPc,20,
                            "ga02_twohop_outer_"+Long.toHexString(callerPc));
                    var branchInsn=full.getListing().getInstructionAt(
                        address(full,0x740L));
                    check(branchInsn!=null &&
                            branchInsn.getMnemonicString()
                                .toUpperCase(Locale.ROOT).startsWith("BNE") &&
                            branchInsn.getFlows().length==1 &&
                            branchInsn.getFlows()[0].equals(address(full,0x746L)) &&
                            full.getListing().getInstructionAt(
                                address(full,0x748L)).getFlowType().isCall(),
                        "Real CPU32 conditional branch or nested JSR not decoded");
                    var realFork=(ghidrassist.hardware.HardwareTwoHopRegisterFlow.Bridge)
                        realBridgeMethod.invoke(null,full,
                            full.getFunctionManager().getFunctionAt(
                                address(full,0x740L)),TaskMonitor.DUMMY);
                    var realOtherBridge=(ghidrassist.hardware.HardwareTwoHopRegisterFlow.Bridge)
                        realBridgeMethod.invoke(null,full,
                            full.getFunctionManager().getFunctionAt(
                                address(full,0x760L)),TaskMonitor.DUMMY);
                    var realTwoStore=(ghidrassist.hardware.HardwareCallsiteRegisterFlow.Callee)
                        realLeafMethod.invoke(null,full,
                            full.getFunctionManager().getFunctionAt(
                                address(full,0x780L)),TaskMonitor.DUMMY);
                    var realOtherLeaf=(ghidrassist.hardware.HardwareCallsiteRegisterFlow.Callee)
                        realLeafMethod.invoke(null,full,
                            full.getFunctionManager().getFunctionAt(
                                address(full,0x7c0L)),TaskMonitor.DUMMY);
                    check(realFork!=null && realFork.complete() &&
                            realFork.steps().size()==6 &&
                            realOtherBridge!=null && realOtherBridge.complete() &&
                            realTwoStore!=null && realTwoStore.complete() &&
                            realTwoStore.steps().size()==3 &&
                            realOtherLeaf!=null && realOtherLeaf.complete(),
                        "Actual branched Ghidra bridge and dual STORE leaf incomplete");
                    var multiOuter=List.of(
                        new ghidrassist.hardware.HardwareCallsiteRegisterFlow.Call(
                            0x900L,0x90cL,0x740L,
                            Map.of("A0",0xfffa00L,"D0",0x40caL),false),
                        new ghidrassist.hardware.HardwareCallsiteRegisterFlow.Call(
                            0x920L,0x92cL,0x740L,
                            Map.of("A0",0xfffa00L,"D0",0x40caL),false),
                        new ghidrassist.hardware.HardwareCallsiteRegisterFlow.Call(
                            0x940L,0x94cL,0x760L,
                            Map.of("A0",0xfffa68L,"D0",0x4848L),false),
                        new ghidrassist.hardware.HardwareCallsiteRegisterFlow.Call(
                            0x960L,0x96cL,0x760L,
                            Map.of("A0",0xfffa68L,"D0",0x4848L),false));
                    var actualMulti=ghidrassist.hardware.HardwareTwoHopRegisterFlow.analyze(
                        multiOuter,List.of(realFork,realOtherBridge),
                        List.of(realTwoStore,realOtherLeaf),
                        Set.of(0xfffa00L,0xfffa68L),48);
                    check(actualMulti.sampled()==4 &&
                            actualMulti.possibleStores()==6 &&
                            actualMulti.rows().size()==6 &&
                            actualMulti.unknownAliases()==0,
                        "Actual CPU32 2-leaf, 3-STORE provenance incomplete");
                    var multiRevision=HardwareAnalysisRevision.capture(
                        full,full.getModificationNumber(),
                        full.getLanguage().getLanguageID().toString(),
                        full.getExecutableSHA256(),true);
                    var multiReport=ghidrassist.hardware.HardwareTwoHopConsensus
                        .markdown(multiOuter,actualMulti,0,20,multiRevision,
                            currentRevision);
                    check(multiReport.contains(
                            "| 0x00000740 | 0x00000780 | 0x00000780 | 2 | SAMPLED_AGREEMENT") &&
                            multiReport.contains(
                            "| 0x00000740 | 0x00000780 | 0x00000782 | 2 | SAMPLED_AGREEMENT") &&
                            multiReport.contains(
                            "| 0x00000760 | 0x000007C0 | 0x000007C0 | 2 | SAMPLED_AGREEMENT") &&
                            multiReport.contains("NOT HARDWARE PROOF"),
                        "Actual Ghidra convergent CALL paths/leaf STORE cohorts mixed");
                    result.addProperty("twohop_real_branch_convergence",true);
                    result.addProperty("twohop_real_multiple_leaf_functions",true);
                    result.addProperty("twohop_real_multiple_store_sites",true);
                    result.addProperty("twohop_actual_listing_revision_invalidation",true);
                    result.addProperty("twohop_actual_listing_rollback_safe",true);
                    result.addProperty("twohop_real_source_provenance_no_stale_apply",true);


                    result.addProperty("twohop_register_width_metadata_readonly",true);
                    result.addProperty("twohop_real_nested_jsr_decoded",true);
                    result.addProperty("twohop_independent_a0_d0",true);
                    result.addProperty("twohop_unknown_alias_not_promoted",true);
                    result.addProperty("twohop_not_review_apply",true);
                    result.addProperty("twohop_repeat_deterministic",true);
                    result.addProperty("twohop_generic_profile_conservative",true);
                    result.addProperty("twohop_read_only",true);
                } else if("two-hop-indexed".equals(ga18Mode)) {
                    // Actual CPU32 disassembly: outer caller passes
                    // A0, D0, D1.W=-1 to a direct JSR bridge.
                    // The bridge copies A0 to A1, then JSR leaf performs
                    // MOVE.W D0,1(A1,D1.W). This must resolve the
                    // 24-bit candidate to A1 without inventing execution.
                    // A separate caller without D1 must remain UNKNOWN.
                    int txIndexed=full.startTransaction(
                        "GA02 isolated two-hop indexed STORE fixture");
                    try {
                        full.getMemory().setBytes(address(full,0x700L),
                            java.util.HexFormat.of().parseHex("338010014e75"));
                        full.getMemory().setBytes(address(full,0x640L),
                            java.util.HexFormat.of().parseHex(
                                "22484eb9000007004e75"));
                        full.getMemory().setBytes(address(full,0x600L),
                            java.util.HexFormat.of().parseHex(
                                "207c00fffa00203c000040ca72ff"+
                                "4eb9000006404e75"));
                        full.getMemory().setBytes(address(full,0x680L),
                            java.util.HexFormat.of().parseHex(
                                "207c00fffa68203c0000484872ff"+
                                "4eb9000006404e75"));
                        full.getMemory().setBytes(address(full,0x6a0L),
                            java.util.HexFormat.of().parseHex(
                                "207c00fffa00203c000040ca"+
                                "4eb9000006404e75"));
                    } finally { full.endTransaction(txIndexed,true); }
                    defineFixtureFunction(full,0x700L,6,
                        "ga02_indexed_leaf_move_w_d0_displ_a1_d1w");
                    defineFixtureFunction(full,0x640L,10,
                        "ga02_indexed_bridge_movea_and_jsr");
                    defineFixtureFunction(full,0x600L,22,
                        "ga02_indexed_simcr_caller");
                    defineFixtureFunction(full,0x680L,22,
                        "ga02_indexed_csbar_caller");
                    defineFixtureFunction(full,0x6a0L,20,
                        "ga02_indexed_unknown_d1_caller");
                    var indexedInsn=full.getListing().getInstructionAt(
                        address(full,0x700L));
                    check(indexedInsn!=null &&
                        indexedInsn.getNumOperands()==2 &&
                        indexedInsn.getMnemonicString().toUpperCase(
                            Locale.ROOT).startsWith("MOVE"),
                        "Ghidra failed to disassemble CPU32 indexed STORE");
                    String indexedOperand=indexedInsn
                        .getDefaultOperandRepresentation(1);
                    var indexed=HardwareIndexedAddress.parse(indexedOperand);
                    check(indexed!=null &&
                        "A1".equals(indexed.base()) &&
                        "D1".equals(indexed.index()) &&
                        indexed.indexBits()==16 &&
                        indexed.scale()==1 && indexed.displacement()==1,
                        "Ghidra actual CPU32 indexed operand was not modeled: "+
                            indexedOperand);
                    var nested=full.getListing().getInstructionAt(
                        address(full,0x642L));
                    var outer=full.getListing().getInstructionAt(
                        address(full,0x60eL));
                    check(nested!=null && nested.getFlowType().isCall() &&
                        nested.getFlows().length==1 &&
                        nested.getFlows()[0].equals(address(full,0x700L)) &&
                        outer!=null && outer.getFlowType().isCall() &&
                        outer.getFlows().length==1 &&
                        outer.getFlows()[0].equals(address(full,0x640L)),
                        "Ghidra actual two direct JSR edges were not decoded");
                    var moveq=full.getListing().getInstructionAt(
                        address(full,0x60cL));
                    check(moveq!=null &&
                        moveq.getMnemonicString().toUpperCase(Locale.ROOT)
                            .startsWith("MOVEQ"),
                        "Ghidra did not decode signed MOVEQ #-1,D1");
                    check(ghidrassist.hardware.HardwareRegisterOperand
                            .isImmediateToken(
                                moveq.getDefaultOperandRepresentation(0),
                                moveq.getMnemonicString()) &&
                            moveq.getScalar(0)!=null,
                        "CPU32 real MOVEQ signed scalar lacked source evidence");
                    long revision=full.getModificationNumber();
                    var report=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    String md=report.markdown;
                    int section=md.indexOf(
                        "## Bounded two-hop CALL argument/MMIO "+
                        "source candidates (GA-02/03)");
                    check(section>=0,"Two-hop indexed source report missing");
                    String source=md.substring(section);
                    check(source.contains(
                        "| 0x00000600 | 0x0000060E | 0x00000640 | "+
                        "0x00000642 | 0x00000700 | 0x00000700 | "+
                        "0x00FFFA00 | 0x000040CA | 16 |") &&
                        source.contains(
                        "| 0x00000680 | 0x0000068E | 0x00000640 | "+
                        "0x00000642 | 0x00000700 | 0x00000700 | "+
                        "0x00FFFA68 | 0x00004848 | 16 |"),
                        "CPU32 indexed address candidate or signed D1.W "+
                        "was lost across direct JSRs: "+
                        source.substring(0,Math.min(4500,source.length())));
                    check(!source.contains("| 0x000006A0 |") &&
                        source.contains("unknown STORE alias: 1"),
                        "Missing D1 incorrectly became a precise MMIO site: "+
                        source.substring(0,Math.min(2200,source.length())));
                    check(report.rawCfgMmioSites.stream().noneMatch(s->
                        s.pc()==0x700L && s.address()==0xfffa00L),
                        "Indexed nested source leaked into Apply-eligible CFG");
                    check(full.getModificationNumber()==revision,
                        "Indexed source analysis changed the Ghidra Program");
                    var again=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    String second=again.markdown.substring(
                        again.markdown.indexOf(
                            "## Bounded two-hop CALL argument/MMIO "));
                    check(second.equals(source) &&
                        full.getModificationNumber()==revision,
                        "Process-local GA-12 replay mixed indexed CALL contexts");
                    var generic=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,false);
                    check(generic.markdown.contains(
                        "Not evaluated: explicit MC68332 profile required") &&
                        !generic.markdown.contains(
                            "| 0x00000600 | 0x0000060E | 0x00000640 |") &&
                        full.getModificationNumber()==revision,
                        "Generic CPU32 inherited MCU-specific indexed MMIO");
                    result.addProperty("twohop_indexed_real_cpu32_decoded",true);
                    result.addProperty("twohop_indexed_real_nested_jsr",true);
                    result.addProperty("twohop_indexed_signed_word",true);
                    result.addProperty("twohop_indexed_context_isolation",true);
                    result.addProperty("twohop_indexed_unknown_d1",true);
                    result.addProperty("twohop_indexed_not_review_apply",true);
                    result.addProperty("twohop_indexed_repeat_deterministic",true);
                    result.addProperty("twohop_indexed_generic_cpu32_safe",true);
                    result.addProperty("twohop_indexed_read_only",true);
                } else if("two-hop-indexed-wrap".equals(ga18Mode)) {
                    // Raw CPU32: A0=0, D1=0xFD00; D1.W=-768 so
                    // -768*2 wraps to SIMCR on the 24-bit bus.
                    // D1=0xFD34 similarly reaches CSBAR. A third
                    // caller never assigns D1 and must stay UNKNOWN.
                    int txWrap=full.startTransaction(
                        "GA02 synthetic two-hop scaled signed index wrap");
                    try {
                        full.getMemory().setBytes(address(full,0x700L),
                            java.util.HexFormat.of().parseHex("338012004e75"));
                        full.getMemory().setBytes(address(full,0x640L),
                            java.util.HexFormat.of().parseHex(
                                "22484eb9000007004e75"));
                        full.getMemory().setBytes(address(full,0x600L),
                            java.util.HexFormat.of().parseHex(
                                "207c00000000203c000040ca223c0000fd00"+
                                "4eb9000006404e75"));
                        full.getMemory().setBytes(address(full,0x680L),
                            java.util.HexFormat.of().parseHex(
                                "207c00000000203c00004848223c0000fd34"+
                                "4eb9000006404e75"));
                        full.getMemory().setBytes(address(full,0x6a0L),
                            java.util.HexFormat.of().parseHex(
                                "207c00000000203c000040ca"+
                                "4eb9000006404e75"));
                    }finally{full.endTransaction(txWrap,true);}
                    defineFixtureFunction(full,0x700L,6,
                        "ga02_wrap_indexed_leaf_move_w");
                    defineFixtureFunction(full,0x640L,10,
                        "ga02_wrap_indexed_bridge");
                    defineFixtureFunction(full,0x600L,26,
                        "ga02_wrap_simcr_caller");
                    defineFixtureFunction(full,0x680L,26,
                        "ga02_wrap_csbar_caller");
                    defineFixtureFunction(full,0x6a0L,20,
                        "ga02_wrap_missing_d1_caller");
                    var wrapInsn=full.getListing().getInstructionAt(
                        address(full,0x700L));
                    check(wrapInsn!=null && wrapInsn.getNumOperands()==2,
                        "Actual CPU32 scaled .W indexed leaf missing");
                    var parsed=HardwareIndexedAddress.parse(
                        wrapInsn.getDefaultOperandRepresentation(1));
                    check(parsed!=null && "A1".equals(parsed.base()) &&
                        "D1".equals(parsed.index()) &&
                        parsed.indexBits()==16 && parsed.scale()==2 &&
                        parsed.displacement()==0,
                        "Real CPU32 scaled operand mismatch: "+
                        wrapInsn.getDefaultOperandRepresentation(1));
                    var nested=full.getListing().getInstructionAt(
                        address(full,0x642L));
                    var outer=full.getListing().getInstructionAt(
                        address(full,0x612L));
                    check(nested!=null && nested.getFlowType().isCall() &&
                        nested.getFlows().length==1 &&
                        nested.getFlows()[0].equals(address(full,0x700L)) &&
                        outer!=null && outer.getFlowType().isCall() &&
                        outer.getFlows().length==1 &&
                        outer.getFlows()[0].equals(address(full,0x640L)),
                        "Two genuine direct CPU32 JSRs not resolved");
                    var d1Literal=full.getListing().getInstructionAt(
                        address(full,0x60cL));
                    check(d1Literal!=null &&
                        d1Literal.getScalar(0)!=null &&
                        d1Literal.getScalar(0).getUnsignedValue()==0xfd00L,
                        "Ghidra did not decode known upper-zero D1 input");
                    long revision=full.getModificationNumber();
                    var report=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    int index=report.markdown.indexOf(
                        "## Bounded two-hop CALL argument/MMIO "+
                        "source candidates (GA-02/03)");
                    check(index>=0,"Two-hop scaled-wrap section missing");
                    String evidence=report.markdown.substring(index);
                    check(evidence.contains(
                        "| 0x00000600 | 0x00000612 | 0x00000640 | "+
                        "0x00000642 | 0x00000700 | 0x00000700 | "+
                        "0x00FFFA00 | 0x000040CA | 16 |") &&
                        evidence.contains(
                        "| 0x00000680 | 0x00000692 | 0x00000640 | "+
                        "0x00000642 | 0x00000700 | 0x00000700 | "+
                        "0x00FFFA68 | 0x00004848 | 16 |"),
                        "Signed D1.W*2 or MCU24 bus wrap lost: "+
                        evidence.substring(0,Math.min(3700,evidence.length())));
                    check(!evidence.contains("| 0x000006A0 |") &&
                        evidence.contains("unknown STORE alias: 1"),
                        "Missing D1 promoted into precise MMIO evidence");
                    check(evidence.contains("SOURCE-ONLY MAY-CANDIDATES") &&
                        evidence.contains("NOT EXECUTION") &&
                        evidence.contains("Review/Apply") &&
                        report.rawCfgMmioSites.stream().noneMatch(site->
                            site.pc()==0x700L && site.address()==0xfffa00L),
                        "Scaled wrap incorrectly became executable Apply");
                    check(full.getModificationNumber()==revision,
                        "Read-only scaled-wrap analysis changed Ghidra Program");
                    var repeated=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(evidence.equals(repeated.markdown.substring(
                        repeated.markdown.indexOf(
                            "## Bounded two-hop CALL argument/MMIO "))) &&
                        full.getModificationNumber()==revision,
                        "GA-12 source replay polluted scaled CALL contexts");
                    var generic=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,false);
                    check(generic.markdown.contains(
                        "Not evaluated: explicit MC68332 profile required") &&
                        !generic.markdown.contains(
                            "| 0x00000600 | 0x00000612 |") &&
                        full.getModificationNumber()==revision,
                        "Generic CPU32 inherited MC68332 scaled MMIO map");
                    result.addProperty("twohop_wrap_cpu32_index_scaled2",true);
                    result.addProperty("twohop_wrap_real_two_jsrs",true);
                    result.addProperty("twohop_wrap_signed_word_not_long",true);
                    result.addProperty("twohop_wrap_simcr_bus24",true);
                    result.addProperty("twohop_wrap_csbar_context_isolated",true);
                    result.addProperty("twohop_wrap_unknown_d1",true);
                    result.addProperty("twohop_wrap_never_review_apply",true);
                    result.addProperty("twohop_wrap_replay_deterministic",true);
                    result.addProperty("twohop_wrap_generic_cpu32_conservative",true);
                    result.addProperty("twohop_wrap_program_read_only",true);
                } else if("indirect-reset-xref".equals(ga18Mode)) {
                    // Real Ghidra CPU32 Listing and user-defined computed
                    // CALL reference. An unproven JSR (A1) cannot become
                    // direct RESET -> SIMCR/MMIO/ISR graph reachability.
                    // Genuine direct JSR (absolute).L remains the control.
                    int txCpu=full.startTransaction(
                        "GA02 test-only computed ref vs RESET CALL");
                    try {
                        full.getMemory().setBytes(address(full,0x600L),
                            java.util.HexFormat.of().parseHex(
                                "4eb9000007004e75"));
                        full.getMemory().setBytes(address(full,0x680L),
                            java.util.HexFormat.of().parseHex("4e914e75"));
                        full.getMemory().setBytes(address(full,0x700L),
                            java.util.HexFormat.of().parseHex(
                                "33fc40ca00fffa004e75"));
                        // Vector #26 points to the MMIO leaf. This is a
                        // static vector pointer only, never an active ISR.
                        full.getMemory().setBytes(address(full,26L*4),
                            java.util.HexFormat.of().parseHex("00000700"));
                    } finally {full.endTransaction(txCpu,true);}
                    defineFixtureFunction(full,0x700L,10,
                        "ga02_reset_indirect_may_mmio_leaf");
                    defineFixtureFunction(full,0x600L,8,
                        "ga02_reset_real_direct_jsr");
                    defineFixtureFunction(full,0x680L,4,
                        "ga02_reset_computed_jsr_a1");
                    var computed=full.getListing().getInstructionAt(
                        address(full,0x680L));
                    var direct=full.getListing().getInstructionAt(
                        address(full,0x600L));
                    check(computed!=null && direct!=null &&
                        computed.getFlowType().isCall() &&
                        computed.getFlowType().isComputed() &&
                        direct.getFlowType().isCall() &&
                        !direct.getFlowType().isComputed(),
                        "Ghidra 12.1.4 must decode JSR (A1) as computed "+
                        "and JSR absolute as direct");
                    int txRef=full.startTransaction(
                        "GA02 test-only false computed CALL xref");
                    try {
                        var reference=full.getReferenceManager().addMemoryReference(
                            address(full,0x680L),address(full,0x700L),
                            RefType.COMPUTED_CALL,SourceType.USER_DEFINED,0);
                        check(reference!=null &&
                            reference.getReferenceType().isCall() &&
                            reference.getToAddress().equals(address(full,0x700L)),
                            "Synthetic computed CALL reference was not created");
                    } finally {full.endTransaction(txRef,true);}
                    var ambiguous=full.getListing().getInstructionAt(
                        address(full,0x680L));
                    check(ambiguous.getReferencesFrom().length>0 &&
                        ambiguous.getFlowType().isComputed() &&
                        ambiguous.getFlowType().isCall(),
                        "Computed CPU32 JSR lost the untrusted CALL ref");
                    // Any returned reference count remains subordinate to
                    // the decoded COMPUTED_CALL bit. When getFlows()
                    // exposes that single injected destination, the old
                    // product would have accepted it as direct CALL.
                    check(!ghidrassist.hardware.HardwareDirectCallGate
                            .directCandidate(true,true,
                                ambiguous.getFlows().length),
                        "Synthetic computed XREF must be ineligible "+
                        "regardless of Ghidra getFlows reference count");
                    check(ghidrassist.hardware.HardwareDirectCallGate
                            .directCandidate(true,false,direct.getFlows().length),
                        "One genuine CPU32 direct JSR still eligible");
                    int txVector=full.startTransaction(
                        "GA02 test-only exact RESET to direct JSR");
                    try {
                        full.getMemory().setBytes(address(full,4L),
                            java.util.HexFormat.of().parseHex("00000600"));
                    } finally {full.endTransaction(txVector,true);}
                    long directRevision=full.getModificationNumber();
                    var exact=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(exact.resetCandidateRecognized &&
                        exact.resetCandidateFunctions.contains(0x600L) &&
                        exact.resetCandidateFunctions.contains(0x700L) &&
                        exact.markdown.contains(
                            "candidate chain 0x00000600 -> 0x00000700") &&
                        exact.markdown.contains(
                            "| 26 | 0x00000700 | 0x00000700 | "+
                            "IN_RESET_STATIC_CALL_SUBSET") &&
                        full.getModificationNumber()==directRevision,
                        "Real direct JSR must remain a static RESET/ISR "+
                        "candidate without any project mutation");
                    int txComputed=full.startTransaction(
                        "GA02 test-only RESET to unproven computed JSR");
                    try {
                        full.getMemory().setBytes(address(full,4L),
                            java.util.HexFormat.of().parseHex("00000680"));
                    } finally {full.endTransaction(txComputed,true);}
                    long computedRevision=full.getModificationNumber();
                    var uncertain=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(uncertain.resetCandidateRecognized &&
                        uncertain.resetGraphIncomplete &&
                        uncertain.resetCandidateFunctions.equals(
                            java.util.Set.of(0x680L)) &&
                        !uncertain.resetCandidateFunctions.contains(0x700L) &&
                        uncertain.markdown.contains(
                            "unresolved call/control-flow: true") &&
                        !uncertain.markdown.contains(
                            "candidate chain 0x00000680 -> 0x00000700") &&
                        uncertain.markdown.contains(
                            "| 26 | 0x00000700 | 0x00000700 | "+
                            "OUTSIDE_OBSERVED_RESET_SUBSET") &&
                        full.getModificationNumber()==computedRevision,
                        "Untrusted computed-CALL reference promoted to "+
                        "reachable RESET/MMIO/ISR source candidates");
                    check(uncertain.markdown.contains(
                            "caller 0x00000680 PC 0x00000680 -> UNKNOWN") &&
                        uncertain.markdown.contains(
                            "unknown callee/flow=true") &&
                        !uncertain.markdown.contains(
                            "caller 0x00000680 PC 0x00000680 -> 0x00000700"),
                        "Computed CALL ref must remain UNKNOWN in "+
                        "interprocedural SIMCR/MM source report");
                    var replay=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(replay.resetCandidateFunctions.equals(
                            java.util.Set.of(0x680L)) &&
                        replay.resetGraphIncomplete &&
                        replay.markdown.contains(
                            "caller 0x00000680 PC 0x00000680 -> UNKNOWN") &&
                        !replay.markdown.contains(
                            "candidate chain 0x00000680 -> 0x00000700") &&
                        full.getModificationNumber()==computedRevision,
                        "GA-12 cache replay must retain unknown computed "+
                        "RESET edge on the identical Program revision");
                    result.addProperty("indirect_reset_real_cpu32_computed",true);
                    result.addProperty("indirect_reset_untrusted_user_xref",true);
                    result.addProperty("indirect_reset_direct_positive_control",true);
                    result.addProperty("indirect_reset_no_false_mmio_isr",true);
                    result.addProperty("indirect_reset_mmio_unknown_propagated",true);
                    result.addProperty("indirect_reset_revision_cache_safe",true);
                    result.addProperty("indirect_reset_read_only_analysis",true);
                } else if("indirect-adjacent".equals(ga18Mode)) {
                    // REAL CPU32: MOVEA.L #0x700,A0 immediately followed
                    // by JSR (A0), never a decoded direct JSR edge.
                    // Negative controls: unknown A1, mismatched A1/A0,
                    // and an immediate pointing to no exact Function.
                    int txIndirect=full.startTransaction(
                        "GA02 isolated proven indirect JSR source fixture");
                    try {
                        full.getMemory().setBytes(address(full,0x600L),
                            java.util.HexFormat.of().parseHex(
                                "207c000007004e904e75"));
                        full.getMemory().setBytes(address(full,0x680L),
                            java.util.HexFormat.of().parseHex("4e914e75"));
                        full.getMemory().setBytes(address(full,0x6a0L),
                            java.util.HexFormat.of().parseHex(
                                "227c000007004e904e75"));
                        full.getMemory().setBytes(address(full,0x6c0L),
                            java.util.HexFormat.of().parseHex(
                                "207c000007204e904e75"));
                        full.getMemory().setBytes(address(full,0x6e0L),
                            java.util.HexFormat.of().parseHex("4e714e75"));
                        full.getMemory().setBytes(address(full,0x700L),
                            java.util.HexFormat.of().parseHex(
                                "33fc40ca00fffa004e75"));
                    }finally {full.endTransaction(txIndirect,true);}
                    defineFixtureFunction(full,0x700L,10,
                        "ga02_indirect_target_simcr_static_store");
                    defineFixtureFunction(full,0x600L,10,
                        "ga02_indirect_adjacent_movea_jsr");
                    defineFixtureFunction(full,0x680L,4,
                        "ga02_indirect_unknown_a1");
                    defineFixtureFunction(full,0x6a0L,10,
                        "ga02_indirect_wrong_register");
                    defineFixtureFunction(full,0x6c0L,10,
                        "ga02_indirect_missing_exact_function");
                    defineFixtureFunction(full,0x6e0L,4,
                        "ga02_noncall_nop_with_untrusted_call_xref");
                    var computed=full.getListing().getInstructionAt(
                        address(full,0x606L));
                    check(computed!=null &&
                        computed.getFlowType().isCall() &&
                        computed.getFlowType().isComputed() &&
                        computed.getNumOperands()==1,
                        "Real Ghidra must decode JSR (A0) as computed CALL");
                    check(ghidrassist.automation.AutomationCallPaths
                            .adjacentConstantRegisterCall(full,computed)
                            .equals(address(full,0x700L)),
                        "Shared Automation API byte-proven indirect target missing");
                    for(long unknownPc:new long[]{
                            0x680L,0x6a6L,0x6c6L}){
                        var unknownInsn=full.getListing().getInstructionAt(
                            address(full,unknownPc));
                        check(unknownInsn!=null &&
                            unknownInsn.getFlowType().isComputed() &&
                            unknownInsn.getFlowType().isCall() &&
                            ghidrassist.automation.AutomationCallPaths
                                .adjacentConstantRegisterCall(
                                    full,unknownInsn)==null,
                            "Unknown computed CALL cannot be inferred at "+
                                Long.toHexString(unknownPc));
                    }
                    // A user-supplied computed-CALL reference is NOT an
                    // exhaustive proof of JSR (A1)'s register value.
                    // The byte verifier knows nothing about A1, so even a
                    // reference to an existing MMIO-writing function must
                    // leave paths COMPLETE=false and this site UNKNOWN.
                    int txRef=full.startTransaction(
                        "GA02 synthetic arbitrary computed CALL xref");
                    try {
                        var xref=full.getReferenceManager().addMemoryReference(
                            address(full,0x680L),address(full,0x700L),
                            RefType.COMPUTED_CALL,
                            SourceType.USER_DEFINED,0);
                        check(xref!=null &&
                            xref.getReferenceType().isCall() &&
                            xref.getToAddress().equals(address(full,0x700L)),
                            "Ghidra failed to create the synthetic unproven CALL ref");
                    } finally {full.endTransaction(txRef,true); }
                    var fake=full.getListing().getInstructionAt(
                        address(full,0x680L));
                    check(fake!=null && fake.getFlowType().isCall() &&
                        fake.getFlowType().isComputed() &&
                        fake.getReferencesFrom().length>0,
                        "The regression must retain a computed JSR with a CALL ref");
                    var unknownPaths=ghidrassist.automation.AutomationCallPaths.query(
                        full,"entry","00000680",8,0,10);
                    check(!unknownPaths.get("complete").getAsBoolean() &&
                        unknownPaths.get("unresolved_calls").getAsInt()==1 &&
                        unknownPaths.get("total_paths").getAsInt()==0 &&
                        unknownPaths.getAsJsonArray("unresolved_call_sites")
                            .toString().contains("00000680") &&
                        unknownPaths.getAsJsonArray("unreachable_entries")
                            .toString().contains("00000700"),
                        "Manual computed-CALL reference must NOT make a "+
                        "JSR (A1) path complete or spuriously reachable: "+
                        unknownPaths);
                    // A user-defined CALL reference on an instruction that
                    // is physically NOT a CALL (here actual CPU32 NOP)
                    // must never invent traversable CALL reachability.
                    int txNopRef=full.startTransaction(
                        "GA02 synthetic CALL XREF on genuine CPU32 NOP");
                    try {
                        var injected=full.getReferenceManager().addMemoryReference(
                            address(full,0x6e0L),address(full,0x700L),
                            RefType.COMPUTED_CALL,
                            SourceType.USER_DEFINED,0);
                        check(injected!=null &&
                            injected.getReferenceType().isCall() &&
                            injected.getToAddress().equals(address(full,0x700L)),
                            "Synthetic misleading CALL XREF on NOP not created");
                    }finally {full.endTransaction(txNopRef,true);}
                    var nop=full.getListing().getInstructionAt(
                        address(full,0x6e0L));
                    check(nop!=null &&
                        "NOP".equalsIgnoreCase(nop.getMnemonicString()) &&
                        !nop.getFlowType().isCall() &&
                        nop.getReferencesFrom().length>0,
                        "Ghidra must keep NOP non-CALL despite user XREF");
                    var fakeNopPaths=ghidrassist.automation.AutomationCallPaths.query(
                        full,"entry","000006E0",8,0,10);
                    check(fakeNopPaths.get("total_paths").getAsInt()==0 &&
                        fakeNopPaths.get("unresolved_calls").getAsInt()==0 &&
                        fakeNopPaths.get("complete").getAsBoolean() &&
                        fakeNopPaths.getAsJsonArray("unreachable_entries")
                            .toString().contains("00000700") &&
                        !fakeNopPaths.getAsJsonArray("reachable_entries")
                            .toString().contains("00000700"),
                        "CALL XREF from a genuine NOP invented a "+
                        "reachable MMIO function: "+fakeNopPaths);
                    var exactPaths=ghidrassist.automation.AutomationCallPaths.query(
                        full,"entry","00000600",8,0,10);
                    check(exactPaths.get("unresolved_calls").getAsInt()==0 &&
                        exactPaths.get("complete").getAsBoolean() &&
                        exactPaths.getAsJsonArray("reachable_entries")
                            .toString().contains("00000700"),
                        "The original byte-proven adjacent JSR (A0) "+
                        "must still resolve: "+exactPaths);
                    long revision=full.getModificationNumber();
                    var report=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    int section=report.markdown.indexOf(
                        "## CPU32 adjacent-immediate indirect JSR source "+
                        "candidates (GA-02/03)");
                    check(section>=0,
                        "Hardware report missing indirect CALL provenance");
                    String evidence=report.markdown.substring(section);
                    check(evidence.contains(
                        "| 0x00000600 | 0x00000600 | 0x00000606 | "+
                        "0x00000700 | adjacent_movea_immediate |") &&
                        evidence.contains("Exact bounded source candidates displayed: 1") &&
                        evidence.contains("unresolved computed calls: 3"),
                        "Proven exact indirect JSR vs 3 UNKNOWN wrong forms: "+
                        evidence.substring(0,Math.min(2500,evidence.length())));
                    check(!evidence.contains("| 0x00000680 |") &&
                        !evidence.contains("| 0x000006A0 |") &&
                        !evidence.contains("| 0x000006C0 |") &&
                        evidence.contains("STATIC SOURCE-ONLY PROVENANCE") &&
                        evidence.contains("NOT EXECUTION") &&
                        evidence.contains("Review/Apply"),
                        "Unknown indirect calls or Apply wrongly promoted");
                    int maySection=evidence.indexOf(
                        "## Byte-witnessed indirect JSR transitive MAY effects");
                    check(maySection>=0,"Missing separately bounded indirect MAY report");
                    int mayEnd=evidence.indexOf(
                        "## One-hop CALL-site A/D register and MMIO candidates",
                        maySection);
                    check(mayEnd>maySection,
                        "Indirect MAY section must end before direct CALL context");
                    String mayEvidence=evidence.substring(maySection,mayEnd);
                    check(mayEvidence.contains("DISPLAY ONLY") &&
                        mayEvidence.contains("NEVER EXECUTION") &&
                        mayEvidence.contains("not a proven MMIO access") &&
                        mayEvidence.contains("Indirect CALL source witnesses: 1") &&
                        mayEvidence.contains(
                            "| 0x00000600 | 0x00000606 | 0x00000700 | "+
                            "STATIC_MAY_CANDIDATE") &&
                        !mayEvidence.contains("| 0x00000680 |") &&
                        !mayEvidence.contains("| 0x000006A0 |") &&
                        !mayEvidence.contains("| 0x000006C0 |"),
                        "Real indirect MAY STORE target must be separate "+
                        "from unverified computed XREFs and direct RESET edges");
                    int mmSource=mayEvidence.indexOf(
                        "## Byte-witnessed indirect JSR SIMCR/MM MAY effects");
                    check(mmSource>=0 &&
                        mayEvidence.substring(mmSource).contains(
                            "| 0x00000600 | 0x00000606 | 0x00000700 | "+
                            "STATIC_MAY_MM_LOW_BYTE") &&
                        !mayEvidence.substring(mmSource).contains(
                            "| 0x00000680 |") &&
                        mayEvidence.substring(mmSource).contains(
                            "NEVER EXECUTION, NEVER APPLY"),
                        "Actual byte-witnessed CPU32 JSR must keep SIMCR/MM "+
                        "source as MAY, separate from unverified JSR paths: "+
                        mayEvidence.substring(0,Math.min(4000,mayEvidence.length())));
                    check(report.rawCfgMmioSites.stream().noneMatch(x->
                        x.pc()==0x606L),
                        "Computed JSR must not become direct CFG write evidence");
                    check(full.getModificationNumber()==revision,
                        "Read-only indirect source audit mutated Program");
                    var repeated=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    String repeatedEvidence=repeated.markdown.substring(
                        repeated.markdown.indexOf(
                            "## CPU32 adjacent-immediate indirect JSR source "));
                    check(repeatedEvidence.equals(evidence) &&
                        full.getModificationNumber()==revision,
                        "Report reused inconsistent indirect JSR source proof");
                    var generic=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,false);
                    check(generic.markdown.contains(
                        "Not evaluated: explicit MC68332 profile required") &&
                        !generic.markdown.contains(
                            "| 0x00000600 | 0x00000600 | 0x00000606 |") &&
                        full.getModificationNumber()==revision,
                        "Generic CPU32 got MCU-specific indirect call proof");
                    result.addProperty("indirect_adjacent_nop_call_xref_denied",true);
                    result.addProperty("indirect_adjacent_real_jsr",true);
                    result.addProperty("indirect_adjacent_shared_api_proof",true);
                    result.addProperty("indirect_adjacent_exact_function",true);
                    result.addProperty("indirect_adjacent_three_unknowns",true);
                    result.addProperty("indirect_adjacent_not_direct_cfg",true);
                    result.addProperty("indirect_adjacent_not_review_apply",true);
                    result.addProperty("indirect_adjacent_static_only",true);
                    result.addProperty("indirect_adjacent_repeat_deterministic",true);
                    result.addProperty("indirect_adjacent_generic_cpu32_safe",true);
                    result.addProperty("indirect_adjacent_untrusted_xref_unknown",true);
                    result.addProperty("indirect_adjacent_byte_proof_preserved",true);
                    result.addProperty("indirect_adjacent_program_read_only",true);
                } else if("indirect-bounded".equals(ga18Mode)) {
                    // Actual CPU32 bytes: one source A0 immediate, followed
                    // by NOP + MOVEQ then JSR (A0); second uses NOP alone.
                    // A CLR.L D0, register mismatch and missing exact target
                    // MUST remain UNKNOWN, not inferred direct CALL edges.
                    int txChain=full.startTransaction(
                        "GA02 isolated bounded CPU32 register indirect JSR");
                    try {
                        full.getMemory().setBytes(address(full,0x600L),
                            java.util.HexFormat.of().parseHex(
                                "207c000007004e7170ff4e904e75"));
                        full.getMemory().setBytes(address(full,0x680L),
                            java.util.HexFormat.of().parseHex(
                                "207c000007004e714e904e75"));
                        full.getMemory().setBytes(address(full,0x6a0L),
                            java.util.HexFormat.of().parseHex(
                                "207c0000070042804e904e75"));
                        full.getMemory().setBytes(address(full,0x6c0L),
                            java.util.HexFormat.of().parseHex(
                                "227c000007004e714e904e75"));
                        full.getMemory().setBytes(address(full,0x6e0L),
                            java.util.HexFormat.of().parseHex(
                                "207c000007204e714e904e75"));
                        full.getMemory().setBytes(address(full,0x700L),
                            java.util.HexFormat.of().parseHex(
                                "33fc40ca00fffa004e75"));
                    }finally {full.endTransaction(txChain,true);}
                    defineFixtureFunction(full,0x700L,10,
                        "ga02_bounded_exact_target_simcr");
                    defineFixtureFunction(full,0x600L,14,
                        "ga02_bounded_nop_moveq_jsr");
                    defineFixtureFunction(full,0x680L,12,
                        "ga02_bounded_nop_jsr");
                    defineFixtureFunction(full,0x6a0L,12,
                        "ga02_bounded_unsupported_clr");
                    defineFixtureFunction(full,0x6c0L,12,
                        "ga02_bounded_mismatched_a1");
                    defineFixtureFunction(full,0x6e0L,12,
                        "ga02_bounded_missing_entry");
                    var safe=full.getListing().getInstructionAt(
                        address(full,0x60aL));
                    var nop=full.getListing().getInstructionAt(
                        address(full,0x688L));
                    check(safe!=null && nop!=null &&
                        safe.getFlowType().isComputed() &&
                        safe.getFlowType().isCall() &&
                        nop.getFlowType().isComputed() &&
                        nop.getFlowType().isCall(),
                        "Real CPU32 bounded JSR(A0) not decoded computed");
                    var safeSource=ghidrassist.automation.AutomationCallPaths.boundedConstantRegisterSource(
                        full,safe,full.getFunctionManager().getFunctionAt(
                            address(full,0x600L)));
                    var nopSource=ghidrassist.automation.AutomationCallPaths.boundedConstantRegisterSource(
                        full,nop,full.getFunctionManager().getFunctionAt(
                            address(full,0x680L)));
                    check(safeSource!=null &&
                        safeSource.movePc().equals(address(full,0x600L)) &&
                        safeSource.target().equals(address(full,0x700L)) &&
                        "bounded_movea_safe_chain".equals(
                            safeSource.evidence()) &&
                        nopSource!=null &&
                        nopSource.movePc().equals(address(full,0x680L)) &&
                        "bounded_movea_nop_chain".equals(nopSource.evidence()),
                        "Shared Automation verifier lost short CPU32 witness");
                    for(long unknownPc:new long[]{0x6a8L,0x6c8L,0x6e8L}){
                        var unknown=full.getListing().getInstructionAt(
                            address(full,unknownPc));
                        check(unknown!=null &&
                            unknown.getFlowType().isCall() &&
                            unknown.getFlowType().isComputed() &&
                            ghidrassist.automation.AutomationCallPaths.boundedConstantRegisterSource(full,unknown,
                                full.getFunctionManager().getFunctionContaining(
                                    unknown.getAddress()))==null,
                            "Unsupported/mismatched/missing indirect target "+
                                Long.toHexString(unknownPc)+" not UNKNOWN");
                    }
                    long revision=full.getModificationNumber();
                    var report=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    int section=report.markdown.indexOf(
                        "## CPU32 adjacent-immediate indirect JSR "+
                        "source candidates (GA-02/03)");
                    check(section>=0,"Bounded computed JSR report absent");
                    String evidence=report.markdown.substring(section);
                    check(evidence.contains(
                        "| 0x00000600 | 0x00000600 | 0x0000060A | "+
                        "0x00000700 | bounded_movea_safe_chain |") &&
                        evidence.contains(
                        "| 0x00000680 | 0x00000680 | 0x00000688 | "+
                        "0x00000700 | bounded_movea_nop_chain |") &&
                        evidence.contains(
                            "Exact bounded source candidates displayed: 2") &&
                        evidence.contains("unresolved computed calls: 3"),
                        "Real short source-only JSR provenance not isolated: "+
                        evidence.substring(0,Math.min(2900,evidence.length())));
                    check(!evidence.contains("| 0x000006A0 |") &&
                        !evidence.contains("| 0x000006C0 |") &&
                        !evidence.contains("| 0x000006E0 |") &&
                        evidence.contains("NOT EXECUTION") &&
                        evidence.contains("Review/Apply") &&
                        evidence.contains("No branch"),
                        "Unsupported chains must not become executed/Apply");
                    int mayPosition=evidence.indexOf(
                        "## Byte-witnessed indirect JSR transitive MAY effects");
                    check(mayPosition>=0,
                        "Bounded MOVEA/JSR MUST expose separate MAY effects");
                    int mayOutputEnd=evidence.indexOf(
                        "## One-hop CALL-site A/D register and MMIO candidates",
                        mayPosition);
                    check(mayOutputEnd>mayPosition,
                        "Bounded MAY section must end before direct CALL context");
                    String mayOutput=evidence.substring(mayPosition,mayOutputEnd);
                    check(mayOutput.contains("Indirect CALL source witnesses: 2") &&
                        mayOutput.contains(
                            "| 0x00000600 | 0x0000060A | 0x00000700 | "+
                            "STATIC_MAY_CANDIDATE") &&
                        mayOutput.contains(
                            "| 0x00000680 | 0x00000688 | 0x00000700 | "+
                            "STATIC_MAY_CANDIDATE") &&
                        !mayOutput.contains("| 0x000006A0 |") &&
                        !mayOutput.contains("| 0x000006C0 |") &&
                        !mayOutput.contains("| 0x000006E0 |") &&
                        mayOutput.contains("No Apply/Undo") &&
                        mayOutput.contains("not a proven MMIO access"),
                        "Bounded indirect may-effects must not promote "+
                        "unverified targets or automatic Ghidra changes: "+
                        mayOutput.substring(0,Math.min(3800,mayOutput.length())));
                    int mmMayStart=mayOutput.indexOf(
                        "## Byte-witnessed indirect JSR SIMCR/MM MAY effects");
                    check(mmMayStart>=0 &&
                        mayOutput.substring(mmMayStart).contains(
                            "| 0x00000600 | 0x0000060A | 0x00000700 | "+
                            "STATIC_MAY_MM_LOW_BYTE") &&
                        mayOutput.substring(mmMayStart).contains(
                            "| 0x00000680 | 0x00000688 | 0x00000700 | "+
                            "STATIC_MAY_MM_LOW_BYTE") &&
                        !mayOutput.substring(mmMayStart).contains(
                            "| 0x000006A0 |") &&
                        !mayOutput.substring(mmMayStart).contains(
                            "| 0x000006C0 |"),
                        "Actual two byte-witnessed CPU32 indirect JSRs "+
                        "must show MAY SIMCR/MM without unverified sources");
                    check(report.rawCfgMmioSites.stream().noneMatch(hit->
                        hit.pc()==0x60aL || hit.pc()==0x688L),
                        "Bounded computed JSR wrongly became Review/Apply");
                    check(full.getModificationNumber()==revision,
                        "Bounded computed JSR audit modified Ghidra Program");
                    var repeated=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    String again=repeated.markdown.substring(
                        repeated.markdown.indexOf(
                            "## CPU32 adjacent-immediate indirect JSR "));
                    check(evidence.equals(again) &&
                        full.getModificationNumber()==revision,
                        "GA-12 cache replay changed bounded indirect evidence");
                    var generic=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,false);
                    check(generic.markdown.contains(
                            "Not evaluated: explicit MC68332 profile required") &&
                        !generic.markdown.contains(
                            "| 0x00000600 | 0x00000600 | 0x0000060A |") &&
                        full.getModificationNumber()==revision,
                        "Generic CPU32 inherited MC68332 indirect sources");
                    result.addProperty("indirect_bounded_real_cpu32_jsrs",true);
                    result.addProperty("indirect_bounded_shared_api_bytes",true);
                    result.addProperty("indirect_bounded_nop_moveq",true);
                    result.addProperty("indirect_bounded_nop_only",true);
                    result.addProperty("indirect_bounded_three_unknowns",true);
                    result.addProperty("indirect_bounded_not_direct_cfg",true);
                    result.addProperty("indirect_bounded_not_review_apply",true);
                    result.addProperty("indirect_bounded_replay_deterministic",true);
                    result.addProperty("indirect_bounded_generic_cpu32_safe",true);
                    result.addProperty("indirect_bounded_program_read_only",true);
                } else if("call-context".equals(ga18Mode) ||
                        "joint-source".equals(ga18Mode)) {
                    boolean jointSource="joint-source".equals(ga18Mode);
                    // Two independent CPU32 callers pass different A/D
                    // arguments to the SAME ordinary direct callee.
                    // Each source-only STORE candidate is tied to its CALL PC,
                    // and never promoted into the global Review/Apply sites.
                    int txContext=full.startTransaction(
                        "GA02 synthetic callsite A/D argument propagation");
                    try {
                        full.getMemory().setBytes(address(full,0x640L),
                            java.util.HexFormat.of().parseHex("30804e75"));
                        full.getMemory().setBytes(address(full,0x600L),
                            java.util.HexFormat.of().parseHex(
                                "207c00fffa00203c000040ca4eb9000006404e75"));
                        full.getMemory().setBytes(address(full,0x680L),
                            java.util.HexFormat.of().parseHex(
                                "207c00fffa68203c000048484eb9000006404e75"));
                        full.getMemory().setBytes(address(full,0x6a0L),
                            java.util.HexFormat.of().parseHex(
                                "203c000040ca4eb9000006404e75"));
                        if(jointSource){
                            // One source image, two independent CALL A/D
                            // contexts AND a third, independent MOVEC VBR
                            // candidate. Neither report proves execution.
                            full.getMemory().setBytes(address(full,0x800L),
                                new byte[1024]);
                            full.getMemory().setBytes(address(full,0x868L),
                                java.util.HexFormat.of().parseHex("00000400"));
                            full.getMemory().setBytes(address(full,0x86cL),
                                java.util.HexFormat.of().parseHex("00000402"));
                            full.getMemory().setBytes(address(full,0x870L),
                                java.util.HexFormat.of().parseHex("00000401"));
                            full.getMemory().setBytes(address(full,0x5a0L),
                                java.util.HexFormat.of().parseHex(
                                    "203c000008004e7b08014e75"));
                        }
                    } finally {full.endTransaction(txContext,true);}
                    defineFixtureFunction(full,0x640L,4,
                        "ga02_arg_callee_move_word_d0_a0");
                    defineFixtureFunction(full,0x600L,20,
                        "ga02_arg_caller_simcr");
                    defineFixtureFunction(full,0x680L,20,
                        "ga02_arg_caller_cs");
                    defineFixtureFunction(full,0x6a0L,14,
                        "ga02_arg_caller_unknown_pointer");
                    if(jointSource)
                        defineFixtureFunction(full,0x5a0L,12,
                            "ga11_joint_source_vbr_register");
                    long revisionBeforeContext=full.getModificationNumber();
                    var interproc=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    String whole=interproc.markdown;
                    int start=whole.indexOf(
                        "## One-hop CALL-site A/D register and MMIO candidates");
                    check(start>=0,"Real Ghidra did not publish source-only "+
                        "CALL-context analysis");
                    String source=whole.substring(start);
                    if(jointSource){
                        String relocatedTitle="### Relocated **source-image** table "+
                            "candidate at 0x00000800";
                        int relocatedAt=whole.indexOf(relocatedTitle);
                        check(relocatedAt>=0 && relocatedAt<start &&
                            whole.contains("runtime VBR UNKNOWN") &&
                            whole.contains("STATIC SOURCE CANDIDATES ONLY"),
                            "Joint CALL-source analysis suppressed GA-11 "+
                            "relocated VBR evidence or promoted active VBR");
                        String relocatedSection=whole.substring(relocatedAt,start);
                        check(relocatedSection.contains(
                            "RECOGNIZED_FUNCTION_CANDIDATE") &&
                            relocatedSection.contains(
                                "INTERIOR_FUNCTION_POINTER_CANDIDATE") &&
                            relocatedSection.contains("ODD_POINTER"),
                            "Joint program lost exact/interior/odd ISR "+
                            "source-image vector classification");
                        check(interproc.rawCfgMmioSites.stream().noneMatch(s->
                            s.pc()==0x640L && s.address()==0xfffa00L),
                            "Joint context CALLEE promoted to global Apply");
                        result.addProperty(
                            "joint_onehop_vbr_same_program",true);
                        result.addProperty(
                            "joint_uncertainty_no_implicit_apply",true);
                        result.addProperty(
                            "joint_relocated_vector_classification",true);
                    }
                    check(source.contains(
                        "| 0x00000600 | 0x0000060C | 0x00000640 | "+
                        "0x00000640 | 0x00FFFA00 | 0x000040CA |") &&
                        source.contains(
                        "| 0x00000680 | 0x0000068C | 0x00000640 | "+
                        "0x00000640 | 0x00FFFA68 | 0x00004848 |"),
                        "Two distinct caller A/D contexts did not preserve "+
                        "their own candidate MMIO address and value: "+
                        source.substring(0,Math.min(3200,source.length())));
                    check(source.contains("unknown STORE aliases: ") &&
                        source.contains("SOURCE-ONLY MAY-CANDIDATES") &&
                        source.contains("No result is published") &&
                        source.contains("No argument convention/actual"),
                        "Caller arguments were promoted to false execution "+
                        "or Review/Apply evidence");
                    // Genuine Ghidra 12.1.4 decoded CPU32: two callers
                    // disagree, third caller cannot prove A0. Reconciliation
                    // must expose only INCOMPLETE sampled source evidence.
                    check(source.contains(
                        "## Cross-CALL MMIO source agreement (GA-02/03)") &&
                        source.contains(
                        "SOURCE-ONLY MAY-CANDIDATES, NEVER HARDWARE PROOF") &&
                        source.contains(
                        "| 0x00000640 | 0x00000640 |") &&
                        source.contains("INCOMPLETE") &&
                        !source.contains("SAMPLED_AGREEMENT"),
                        "Real mixed CALL contexts promoted partial source "+
                        "inventory to an apparent global MMIO effect");
                    check(interproc.rawCfgMmioSites.stream().noneMatch(s->
                        s.pc()==0x640L && s.address()==0xfffa00L),
                        "Contextual source-only MMIO was promoted to "+
                        "function-global Review/Apply proof");
                    check(full.getModificationNumber()==revisionBeforeContext,
                        "Per-CALL argument analysis edited Program");
                    var genericContext=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,false);
                    check(genericContext.markdown.contains(
                        "Generic CPU32 does not imply MCU MMIO") &&
                        !genericContext.markdown.contains(
                            "| 0x00000600 | 0x0000060C | 0x00000640 |"),
                        "MC68332 candidate leaked into generic CPU32");
                    check(full.getModificationNumber()==revisionBeforeContext,
                        "Generic-profile negative analysis edited Program");
                    if(jointSource){
                        check(genericContext.markdown.contains(
                            "Not evaluated: MC68332 profile not explicitly selected") &&
                            !genericContext.markdown.contains(
                                "### Relocated **source-image** table candidate"),
                            "Joint source-image VBR device assumption leaked "+
                            "into generic CPU32");
                        result.addProperty("joint_generic_profile_off",true);
                        result.addProperty("joint_program_read_only",true);
                    }
                    result.addProperty("arg_direct_call_real_ghidra",true);
                    result.addProperty("arg_independent_call_sites",true);
                    result.addProperty("arg_unknown_alias_not_promoted",true);
                    result.addProperty("arg_not_review_apply",true);
                    result.addProperty("arg_generic_profile_conservative",true);
                    result.addProperty("arg_read_only",true);
                } else if("leaf-return".equals(ga18Mode)) {
                    // Genuine CPU32 Listing, with real Ghidra callee reference.
                    // Only strict direct leaf return constants cross the
                    // generic CALL barrier; memory/MM state remains unknown.
                    int t=full.startTransaction("GA02 synthetic verified leaf");
                    try{
                        full.getMemory().setBytes(address(full,0x640L),
                            java.util.HexFormat.of().parseHex(
                                "207c00fffa00203c000040ca4e75"));
                        full.getMemory().setBytes(address(full,0x600L),
                            java.util.HexFormat.of().parseHex(
                                "4eb90000064030804e75"));
                        full.getMemory().setBytes(address(full,0x680L),
                            java.util.HexFormat.of().parseHex(
                                "207c00fffa004eb90000040030bc40ca4e75"));
                    }finally{full.endTransaction(t,true);}
                    defineFixtureFunction(full,0x640L,14,"fixture_leaf_returns_both");
                    defineFixtureFunction(full,0x600L,10,"fixture_leaf_call_positive");
                    defineFixtureFunction(full,0x680L,18,"fixture_unverified_call_negative");
                    long revision=full.getModificationNumber();
                    var evidence=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    check(evidence.markdown.contains(
                        "- Strictly verified leaf CALL return-register sites: 1"),
                        "MC68332 source did not accept unique direct leaf");
                    var callee=full.getFunctionManager().getFunctionAt(
                        address(full,0x640L));
                    var postCall=full.getListing().getInstructionAt(
                        address(full,0x606L));
                    var transMethod=GhidraHardwareFlowService.class
                        .getDeclaredMethod("translate",
                            ghidra.program.model.listing.Instruction.class,
                            Function.class);
                    transMethod.setAccessible(true);
                    var modeled=(ghidrassist.hardware.HardwareDataflow.Step)
                        transMethod.invoke(null,postCall,
                            full.getFunctionManager().getFunctionAt(
                                address(full,0x600L)));
                    var leafMethod=GhidraHardwareFlowService.class
                        .getDeclaredMethod("verifiedLeafReturn",
                            Program.class,Function.class,TaskMonitor.class);
                    leafMethod.setAccessible(true);
                    var proved=leafMethod.invoke(null,full,callee,TaskMonitor.DUMMY);
                    System.out.println("GA02 SYNTHETIC LEAF DIAG"+
                        " opcode="+postCall.getMnemonicString()+
                        " srcOperand="+postCall.getDefaultOperandRepresentation(0)+
                        " modeledSource="+modeled.sourceRegister+
                        " modeledKind="+modeled.kind+
                        " knownLeafReturns="+proved);
                    check(evidence.rawCfgMmioSites.stream().anyMatch(site->
                        site.pc()==0x606L && site.address()==0xfffa00L &&
                        "SIMCR".equals(site.register()) &&
                        Integer.valueOf(0x40ca).equals(site.literal()) &&
                        site.unknownCall()),
                        "Real leaf-return register values not recovered conservatively: "+
                        evidence.rawCfgMmioSites.stream()
                            .filter(site->site.pc()>=0x600L &&
                                site.pc()<0x690L)
                            .map(site->"pc="+Long.toHexString(site.pc())+
                                ",reg="+site.register()+
                                ",addr="+Long.toHexString(site.address())+
                                ",literal="+site.literal()+
                                ",unknownCall="+site.unknownCall())
                            .toList());
                    check(evidence.rawCfgMmioSites.stream().anyMatch(site->
                        site.pc()==0x68cL &&
                        "UNRESOLVED_ALIAS".equals(site.register())),
                        "Unverified callee incorrectly preserved pre-call A0");
                    check(full.getModificationNumber()==revision,
                        "Read-only verified leaf analysis edited Ghidra Program");
                    var generic=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,false);
                    check(generic.markdown.contains(
                        "- Strictly verified leaf CALL return-register sites: 0"),
                        "Generic CPU32 inherited MC68332-only leaf evidence");
                    result.addProperty("leaf_real_direct_return_constants",true);
                    result.addProperty("leaf_real_call_barrier_history_unknown",true);
                    result.addProperty("leaf_real_unproved_call_keeps_alias",true);
                    result.addProperty("leaf_real_generic_profile_conservative",true);
                    result.addProperty("leaf_real_program_read_only",true);
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

                } else if("function-stage-resume".equals(ga18Mode)) {
                    // Real synthetic Ghidra with >=2 disassembled functions.
                    // Cancel the *whole* CFG stage immediately AFTER one
                    // individual fixed point was completely published in
                    // process-local function-stage cache; never publish a
                    // partial full Report or Review/RAG on cancellation.
                    HardwareFlowStageCache.clear(full);
                    ghidrassist.hardware.HardwareEvidenceCache.clear(full);
                    long rev=full.getModificationNumber();
                    HardwareAnalysisRevision started=HardwareAnalysisRevision.capture(
                        full,rev,full.getLanguageID().toString(),
                        full.getExecutableSHA256(),true);
                    check(full.getFunctionManager().getFunctionCount()>=2,
                        "Fixture lacks two independent real Ghidra functions");
                    java.util.concurrent.atomic.AtomicInteger checks=
                        new java.util.concurrent.atomic.AtomicInteger();
                    final Program observedProgram=full;
                    TaskMonitor interrupt=(TaskMonitor)java.lang.reflect.Proxy
                        .newProxyInstance(TaskMonitor.class.getClassLoader(),
                            new Class[]{TaskMonitor.class},(proxy,method,args2)-> {
                            if(method.getName().equals("checkCancelled")) {
                                checks.incrementAndGet();
                                if(GhidraHardwareFlowService
                                        .checkpointedFunctionStages(observedProgram)>0)
                                    throw new CancelledException();
                                return null;
                            }
                            return method.invoke(TaskMonitor.DUMMY,args2);
                        });
                    boolean cancelled=false;
                    try{
                        HardwareFlowStageCache.loadOrAnalyze(
                            full,started,interrupt);
                    }catch(CancelledException expected){cancelled=true;}
                    int completed=GhidraHardwareFlowService
                        .checkpointedFunctionStages(full);
                    check(cancelled && completed>=1 && checks.get()>0,
                        "Real task did not cancel after a completed function");
                    check(!ghidrassist.hardware.HardwareEvidenceCache.hasEvidence(full),
                        "Cancelled scan published RAG before full completion");
                    check(full.getModificationNumber()==rev,
                        "Partial CFG did a Ghidra database edit");
                    var resumed=HardwareFlowStageCache.loadOrAnalyze(
                        full,started,TaskMonitor.DUMMY);
                    check(!resumed.reused() &&
                        resumed.report().markdown.contains(
                            "- Completed per-function fixed points reused: ") &&
                        !resumed.report().markdown.contains(
                            "- Completed per-function fixed points reused: 0;"),
                        "Same-program retry discarded completed function work");
                    var again=HardwareFlowStageCache.loadOrAnalyze(
                        full,started,TaskMonitor.DUMMY);
                    check(again.reused() && again.report()==resumed.report(),
                        "Full completion did not retain full-stage cache");
                    HardwareFlowStageCache.clear(full);
                    check(GhidraHardwareFlowService
                            .checkpointedFunctionStages(full)==0,
                        "Explicit invalidation kept stale partial fixed points");
                    var clean=HardwareFlowStageCache.loadOrAnalyze(
                        full,started,TaskMonitor.DUMMY);
                    check(!clean.reused() &&
                        clean.report().markdown.contains(
                            "- Completed per-function fixed points reused: 0;") &&
                        full.getModificationNumber()==rev,
                        "Explicit invalidate did not force recomputation");
                    check(!ghidrassist.hardware.HardwareEvidenceCache.hasEvidence(full),
                        "Function checkpoints published AI/RAG without Apply");
                    result.addProperty("function_stage_real_partial_cancelled",true);
                    result.addProperty("function_stage_completed_before_cancel",true);
                    result.addProperty("function_stage_retry_reused",true);
                    result.addProperty("function_stage_full_then_reused",true);
                    result.addProperty("function_stage_explicit_clear_invalidated",true);
                    result.addProperty("function_stage_no_partial_rag_or_edits",true);

                } else if("agentic-evidence".equals(ga18Mode)) {
                    // GA-12/15: genuine isolated Ghidra Program source identity,
                    // but deterministic synthetic observations: NO AI model.
                    var evidence=new ghidrassist.agent.react.FindingsCache(2);
                    evidence.addFinding("register SIMCR at static PC 0x100",
                        "synthetic listing: 0x100","listing",9);
                    evidence.addFinding("candidate VBR source 0x200",
                        "synthetic MOVEC, not executed","listing",6);
                    var bridge=ghidrassist.agent.react.AgenticEvidenceRegistry.shared();
                    long rev=full.getModificationNumber();
                    String importSha=full.getExecutableSHA256();
                    String run=bridge.begin(full,rev,importSha,evidence);
                    var first=bridge.page(full,rev,importSha,0,1,null,null);
                    check(first.run().equals(run) &&
                        first.state().equals("RUNNING") &&
                        !first.complete() && first.findings().hasMore(),
                        "Real Ghidra Program must bind running Agentic evidence");
                    var second=bridge.page(full,rev,importSha,1,1,
                        first.run(),first.findings().revision());
                    check(second.findings().rows().size()==1 &&
                        second.findings().rows().get(0).fact().contains("VBR") &&
                        !second.findings().hasMore(),
                        "Real Ghidra Program must paginate retained findings");
                    boolean refused=false;
                    try {
                        bridge.page(full,rev+1,importSha,0,1,null,null);
                    } catch(IllegalStateException expected) { refused=true; }
                    check(refused,"Changed Ghidra Program revision must reject evidence");
                    bridge.finish(full,evidence,"SUCCESS");
                    check(bridge.page(full,rev,importSha,0,2,null,null).complete(),
                        "Completed real Program source may export retained evidence");
                    evidence.addFinding("later high relevance observation",
                        "synthetic third source","xref",10);
                    refused=false;
                    try {
                        bridge.page(full,rev,importSha,1,1,
                            first.run(),first.findings().revision());
                    } catch(IllegalStateException expected) { refused=true; }
                    check(refused && !bridge.page(full,rev,importSha,0,2,
                            null,null).complete(),
                        "Pruning/stale evidence pages cannot be marked complete");
                    evidence.extractFromToolOutput("mcp",
                        ("buffer overflow unexamined hardware line\\n").repeat(6000));
                    check(evidence.isSourceIncomplete() &&
                        bridge.page(full,rev,importSha,0,2,null,null)
                            .findings().sourceIncomplete() &&
                        !bridge.page(full,rev,importSha,0,2,null,null)
                            .complete(),
                        "Unread tool source is not complete Agentic evidence");
                    bridge.invalidate(full);
                    check(full.getModificationNumber()==rev,
                        "Agentic evidence bridge must not mutate real Ghidra Program");
                    result.addProperty("agentic_real_program_bounded_pages",true);
                    result.addProperty("agentic_real_program_revision_guard",true);
                    result.addProperty("agentic_source_incomplete_remains_explicit",true);
                    result.addProperty("agentic_read_only_revision_unchanged",true);
                } else if("scoped-variable".equals(ga18Mode)) {
                    // GA-05/08: real Ghidra Function DB variables, not decompiler
                    // temporary HighVariables or A-register aliases.
                    byte[] code=java.util.HexFormat.of().parseHex(
                        "33fc387c00fffa4c33fc7c3000fffa4e" +
                        "33fc2f7f00fffa444e75");
                    int setup=full.startTransaction("GA-05/08 isolated pointer fixtures");
                    try {
                        full.getMemory().setBytes(address(full,0x5a0L),code);
                    } finally {full.endTransaction(setup,true);}
                    defineFixtureFunction(full,0x5a0L,26,"FUN_000005A0");
                    Function fn=full.getFunctionManager().getFunctionAt(
                        address(full,0x5a0L));
                    check(fn!=null,"No real Ghidra test Function");
                    var ptr=new ghidra.program.model.data.PointerDataType();
                    int vars=full.startTransaction("GA-05/08 test-only typed pointer variables");
                    try {
                        fn.addParameter(new ghidra.program.model.listing.ParameterImpl(
                            "param_1",ptr,8,full,SourceType.DEFAULT),SourceType.DEFAULT);
                        fn.addLocalVariable(new ghidra.program.model.listing.LocalVariableImpl(
                            "local_8",ptr,-8,full,SourceType.DEFAULT),SourceType.DEFAULT);
                    } finally {full.endTransaction(vars,true);}
                    var candidates=ghidrassist.hardware.HardwareScopedVariableService
                        .preview(fn);
                    check(candidates.size()==2 &&
                          candidates.stream().allMatch(p->p.decision() ==
                            ghidrassist.hardware.HardwareScopedVariableReview
                                .Decision.READY),
                        "Real pointer parameter/local preview must be READY: "+
                            candidates.toString());
                    var reviewed=HardwareAnalysisRevision.capture(
                        full,full.getModificationNumber(),
                        full.getLanguageID().toString(),
                        full.getExecutableSHA256(),true);
                    // Deliberately corrupt the second selected identity.
                    var second=candidates.get(1);
                    var orig=second.original();
                    var fake=new ghidrassist.hardware.HardwareScopedVariableReview
                        .Observation(orig.functionEntry(),orig.currentName(),
                            orig.kind(),orig.ordinal(),orig.storage()+"_other",
                            orig.pointerType(),orig.userDefined(),
                            orig.autoParameter());
                    var invalid=new ghidrassist.hardware.HardwareScopedVariableReview
                        .Proposal(fake,second.proposedName(),second.decision());
                    boolean refused=false;
                    try {
                        ghidrassist.hardware.HardwareScopedVariableService.apply(
                            full,List.of(candidates.get(0),invalid),reviewed);
                    } catch(IllegalStateException expected){refused=true;}
                    check(refused && ghidrassist.hardware.HardwareScopedVariableService
                            .preview(fn).stream().allMatch(p->p.decision() ==
                                ghidrassist.hardware.HardwareScopedVariableReview
                                    .Decision.READY),
                        "Ghidra failed identity in second row must roll back all names");
                    // A failed Program transaction may increment Ghidra's
                    // modification counter even after rollback. Explicit
                    // re-review is necessary before the successful batch.
                    var cleanRevision=HardwareAnalysisRevision.capture(
                        full,full.getModificationNumber(),
                        full.getLanguageID().toString(),
                        full.getExecutableSHA256(),true);
                    var scopedOutcome=ghidrassist.hardware.HardwareScopedVariableService.apply(
                        full,candidates,cleanRevision);
                    check(scopedOutcome.renamed()==2,
                        "Explicit approved Ghidra pointer variable batch must rename both");
                    var after=ghidrassist.hardware.HardwareScopedVariableService.preview(fn);
                    check(after.size()==2 && after.stream().allMatch(
                        p->p.decision()==ghidrassist.hardware.HardwareScopedVariableReview
                            .Decision.USER_NAMED),
                        "Renamed pointer types must protect existing user names");
                    check(full.canUndo(),"Native Ghidra Undo missing after pointer Apply");
                    full.undo();
                    check(ghidrassist.hardware.HardwareScopedVariableService.preview(fn)
                            .stream().allMatch(p->p.decision()==
                                ghidrassist.hardware.HardwareScopedVariableReview
                                    .Decision.READY),
                        "Native Undo must restore original argument/local names");
                    check(full.canRedo(),"Native Ghidra Redo missing after pointer Undo");
                    full.redo();
                    check(ghidrassist.hardware.HardwareScopedVariableService.preview(fn)
                            .stream().allMatch(p->p.decision()==
                                ghidrassist.hardware.HardwareScopedVariableReview
                                    .Decision.USER_NAMED),
                        "Native Redo must restore both explicitly approved names");
                    boolean stale=false;
                    try {
                        ghidrassist.hardware.HardwareScopedVariableService.apply(
                            full,candidates,reviewed);
                    }catch(IllegalStateException expected){stale=true;}
                    check(stale,"Replay after Ghidra Undo/Redo must reject old approval");
                    result.addProperty("scoped_real_pointer_param_local",true);
                    result.addProperty("scoped_atomic_rejection",true);
                    result.addProperty("scoped_explicit_apply",true);
                    result.addProperty("scoped_native_undo_redo",true);
                    result.addProperty("scoped_stale_revision_rejected",true);
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
                    var collisionRevision=
                        ghidrassist.hardware.HardwareAnalysisRevision.capture(
                            full,full.getModificationNumber(),
                            full.getLanguageID().toString(),
                            full.getExecutableSHA256(),true);
                    boolean rolledBack=false;
                    try {
                        ghidrassist.hardware.HardwareFunctionRenameService.apply(
                            full,List.of(first,second),collisionRevision);
                    }catch(IllegalStateException expected) {rolledBack=true;}
                    check(rolledBack &&
                          fn1.getName().equals(firstName) &&
                          fn2.getName().equals(secondName) &&
                          ghidrassist.hardware.HardwareFunctionRenameService
                              .receipt(full,0x5a0L).isEmpty() &&
                          ghidrassist.hardware.HardwareFunctionRenameService
                              .receipt(full,0x640L).isEmpty(),
                        "Failed approval must roll back both names and receipts");
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
                    // Removing the conflicting test symbol modifies Ghidra
                    // even though target function names remain unchanged.
                    // The previous review receipt must no longer authorize
                    // the mutation. Fresh explicit Review is required.
                    boolean staleDenied=false;
                    try {
                        ghidrassist.hardware.HardwareFunctionRenameService.apply(
                            full,List.of(first,second),collisionRevision);
                    }catch(IllegalStateException expected){staleDenied=true;}
                    check(staleDenied &&
                          fn1.getName().equals(firstName) &&
                          fn2.getName().equals(secondName),
                        "Stale review receipt after symbol edit must reject renames");
                    var reviewedRevision=
                        ghidrassist.hardware.HardwareAnalysisRevision.capture(
                            full,full.getModificationNumber(),
                            full.getLanguageID().toString(),
                            full.getExecutableSHA256(),true);
                    var renamed=ghidrassist.hardware.HardwareFunctionRenameService
                        .apply(full,List.of(first,second),reviewedRevision);
                    check(renamed.renamed()==2 &&
                          fn1.getName().equals(first.proposedName) &&
                          fn2.getName().equals(second.proposedName),
                        "Actual Ghidra USER_DEFINED function rename failed");
                    var receipt1=ghidrassist.hardware.HardwareFunctionRenameService
                        .receipt(full,0x5a0L).orElseThrow();
                    var receipt2=ghidrassist.hardware.HardwareFunctionRenameService
                        .receipt(full,0x640L).orElseThrow();
                    check(receipt1.entry()==0x5a0L &&
                          receipt2.entry()==0x640L &&
                          receipt1.reviewedModification()==
                              reviewedRevision.modificationNumber() &&
                          receipt2.reviewedModification()==
                              reviewedRevision.modificationNumber() &&
                          receipt1.beforeName().equals(firstName) &&
                          receipt1.afterName().equals(first.proposedName) &&
                          receipt2.beforeName().equals(secondName) &&
                          receipt2.afterName().equals(second.proposedName) &&
                          receipt1.sourceSha256().equals(
                              full.getExecutableSHA256()==null ?
                                  "UNKNOWN":full.getExecutableSHA256()) &&
                          receipt1.registers().contains("CSBAR") &&
                          receipt1.operationOrigin().contains("actor UNKNOWN"),
                        "Persistent per-function receipt lacks source, revision or origin");
                    String persisted=full.getOptions(
                        ghidrassist.hardware.HardwareFunctionRenameReceipt
                            .OPTIONS_CATEGORY).getString(
                            ghidrassist.hardware.HardwareFunctionRenameReceipt
                                .optionKey(0x5a0L),null);
                    check(persisted!=null &&
                          ghidrassist.hardware.HardwareFunctionRenameReceipt
                            .decode(persisted).equals(receipt1),
                        "Ghidra Program Options do not preserve canonical GA-13 receipt");
                    // GA-13 audit: two approved, address-ordered operations,
                    // with live SourceType and no Program database mutation.
                    long auditRevision=full.getModificationNumber();
                    var approvedAudit=ghidrassist.hardware.HardwareFunctionRenameService
                        .audit(full);
                    check(approvedAudit.rows().size()==2 &&
                          approvedAudit.count(ghidrassist.hardware
                            .HardwareFunctionRenameAudit.State.CURRENT_APPROVED_NAME)==2 &&
                          approvedAudit.rows().get(0).receipt().entry()==0x5a0L &&
                          approvedAudit.rows().get(1).receipt().entry()==0x640L &&
                          approvedAudit.csv().contains("actor UNKNOWN") &&
                          full.getModificationNumber()==auditRevision,
                        "Real Ghidra audit failed to reconcile two approved names");
                    result.addProperty("ga13_rename_audit_two_approved",true);
                    check(full.canUndo(),"Real Ghidra Undo unavailable after renames");
                    full.undo();
                    check(fn1.getName().equals(firstName) &&
                          fn2.getName().equals(secondName) &&
                          ghidrassist.hardware.HardwareFunctionRenameService
                              .receipt(full,0x5a0L).isEmpty() &&
                          ghidrassist.hardware.HardwareFunctionRenameService
                              .receipt(full,0x640L).isEmpty(),
                        "Ghidra native Undo must restore function names AND provenance");
                    check(ghidrassist.hardware.HardwareFunctionRenameService.audit(full)
                            .rows().isEmpty(),
                        "Native Undo must remove reverted operation receipts from current audit");
                    check(full.canRedo(),"Ghidra Redo unavailable for receipt transaction");
                    full.redo();
                    check(fn1.getName().equals(first.proposedName) &&
                          fn2.getName().equals(second.proposedName) &&
                          ghidrassist.hardware.HardwareFunctionRenameService
                              .receipt(full,0x5a0L).orElseThrow().equals(receipt1) &&
                          ghidrassist.hardware.HardwareFunctionRenameService
                              .receipt(full,0x640L).orElseThrow().equals(receipt2),
                        "Ghidra Redo must restore BOTH names and exact GA-13 receipts");
                    check(ghidrassist.hardware.HardwareFunctionRenameService.audit(full)
                            .rows().equals(approvedAudit.rows()),
                        "Redo must restore exact persistent audit snapshot");
                    full.undo();
                    check(fn1.getName().equals(firstName) &&
                          fn2.getName().equals(secondName) &&
                          ghidrassist.hardware.HardwareFunctionRenameService
                              .receipt(full,0x5a0L).isEmpty() &&
                          ghidrassist.hardware.HardwareFunctionRenameService
                              .receipt(full,0x640L).isEmpty(),
                        "Second Undo must again clear both receipt and name");
                    check(ghidrassist.hardware.HardwareFunctionRenameService.audit(full)
                            .rows().isEmpty(),
                        "Second Undo must not leave a false durable audit event");
                    result.addProperty("ga13_rename_audit_undo_redo_correlated",true);
                    result.addProperty("rename_real_functions_and_collision",true);
                    result.addProperty("rename_atomic_rollback",true);
                    result.addProperty("rename_stale_revision_blocked",true);
                    result.addProperty("rename_transactional_two_function_apply",true);
                    result.addProperty("rename_native_undo_restored",true);
                    result.addProperty("rename_program_options_receipt_written",true);
                    result.addProperty("rename_atomic_receipt_rollback",true);
                    result.addProperty("rename_receipt_native_undo_redo",true);
                    result.addProperty("rename_receipt_actor_remains_unknown",true);
                } else if("receipt-restart-write".equals(ga18Mode)) {
                    // Real Ghidra first JVM: persist an approved rename and
                    // its GA-13 receipt in an isolated project database.
                    // The wrapper MUST spawn a second distinct Java process
                    // which reopens this same saved project from disk.
                    byte[] code=java.util.HexFormat.of().parseHex(
                        "33fc387c00fffa4c33fc7c3000fffa4e" +
                        "33fc2f7f00fffa444e75");
                    int tx=full.startTransaction("GA13 cross-JVM synthetic rename source");
                    try {
                        full.getMemory().setBytes(address(full,0x5a0L),code);
                    } finally {full.endTransaction(tx,true);}
                    defineFixtureFunction(full,0x5a0L,26,"FUN_000005A0");
                    Function target=full.getFunctionManager()
                        .getFunctionAt(address(full,0x5a0L));
                    check(target!=null &&
                        target.getName().matches("(?i)FUN_[0-9A-F]{8}"),
                        "First JVM original function name invalid: "+
                            (target==null?"NULL":target.getName()));
                    // Ghidra canonicalizes auto-generated FUN hex case.
                    // Always bind the proposal to its actual on-disk
                    // current name, never a hard-coded fixture spelling.
                    String originalName=target.getName();
                    var observations=List.of(
                        new ghidrassist.hardware.HardwareFunctionNamingReview
                            .Observation(0x5a0L,originalName,0x5a0L,
                                "CSPAR0",true),
                        new ghidrassist.hardware.HardwareFunctionNamingReview
                            .Observation(0x5a0L,originalName,0x5a8L,
                                "CSBAR0",true),
                        new ghidrassist.hardware.HardwareFunctionNamingReview
                            .Observation(0x5a0L,originalName,0x5b0L,
                                "CSOR0",true));
                    var proposal=ghidrassist.hardware.HardwareFunctionNamingReview
                        .propose(true,observations,List.of()).get(0);
                    var reviewed=ghidrassist.hardware.HardwareAnalysisRevision.capture(
                        full,full.getModificationNumber(),
                        full.getLanguageID().toString(),
                        full.getExecutableSHA256(),true);
                    var renamed=ghidrassist.hardware.HardwareFunctionRenameService
                        .apply(full,List.of(proposal),reviewed);
                    var receipt=ghidrassist.hardware.HardwareFunctionRenameService
                        .receipt(full,0x5a0L).orElseThrow();
                    check(renamed.renamed()==1 &&
                        receipt.beforeName().equals(originalName) &&
                        receipt.afterName().equals(target.getName()) &&
                        receipt.reviewedModification()==reviewed.modificationNumber(),
                        "First JVM failed to persist approved rename and evidence");
                    // The prior test only checked Undo/Redo in one JVM.
                    // This explicitly saves a genuine Ghidra Program DB.
                    full.save("GA-13 synthetic rename receipt cross-JVM",TaskMonitor.DUMMY);
                    result.addProperty("rename_receipt_first_jvm_saved",true);
                    result.addProperty("rename_receipt_first_jvm_source",true);
                    result.addProperty("ga13_receipt_before",receipt.beforeName());
                    result.addProperty("ga13_receipt_after",receipt.afterName());
                    result.addProperty("ga13_receipt_revision",
                        receipt.reviewedModification());
                    result.addProperty("ga13_receipt_source_sha",
                        receipt.sourceSha256());
                    result.addProperty("ga13_process_pid",
                        ProcessHandle.current().pid());
                } else if("receipt-restart-read".equals(ga18Mode)) {
                    // Real Ghidra second JVM: the wrapper has not re-imported
                    // the fixture, and did not pass the first Program object.
                    // Names AND Program-local operation record must survive.
                    long unchanged=full.getModificationNumber();
                    Function renamed=full.getFunctionManager()
                        .getFunctionAt(address(full,0x5a0L));
                    check(renamed!=null &&
                        "HW_MC68332_CONFIGURE_CHIP_SELECTS_CANDIDATE_000005A0"
                            .equals(renamed.getName()),
                        "Second JVM did not load saved approved function name");
                    var receipt=ghidrassist.hardware.HardwareFunctionRenameService
                        .receipt(full,0x5a0L).orElseThrow();
                    check(receipt.entry()==0x5a0L &&
                        receipt.beforeName().matches("(?i)FUN_[0-9A-F]{8}") &&
                        receipt.afterName().equals(renamed.getName()) &&
                        receipt.writeSites()==3 &&
                        "CONFIGURE_CHIP_SELECTS".equals(receipt.role()) &&
                        receipt.reviewedModification()>=0 &&
                        receipt.sourceSha256().equals(
                            full.getExecutableSHA256()==null ?
                                "UNKNOWN":full.getExecutableSHA256()) &&
                        receipt.registers().contains("CSBAR0") &&
                        receipt.operationOrigin().contains("actor UNKNOWN"),
                        "Second JVM lost GA-13 versioned Program operation history");
                    String stored=full.getOptions(
                        ghidrassist.hardware.HardwareFunctionRenameReceipt
                            .OPTIONS_CATEGORY).getString(
                            ghidrassist.hardware.HardwareFunctionRenameReceipt
                                .optionKey(0x5a0L),null);
                    check(stored!=null &&
                        ghidrassist.hardware.HardwareFunctionRenameReceipt
                            .decode(stored).equals(receipt),
                        "Second JVM found noncanonical or missing Options record");
                    var reloadedAudit=ghidrassist.hardware.HardwareFunctionRenameService
                        .audit(full);
                    check(reloadedAudit.rows().size()==1 &&
                          reloadedAudit.count(ghidrassist.hardware
                            .HardwareFunctionRenameAudit.State.CURRENT_APPROVED_NAME)==1 &&
                          reloadedAudit.rows().get(0).receipt().equals(receipt) &&
                          reloadedAudit.csv().contains("actor UNKNOWN"),
                        "Distinct second JVM must retain current rename audit identity");
                    check(full.getModificationNumber()==unchanged,
                        "Reading persisted receipt and audit must never edit Ghidra Program");
                    result.addProperty("ga13_restart_audit_read_only",true);
                    result.addProperty("rename_receipt_second_jvm_reopened",true);
                    result.addProperty("rename_receipt_saved_name_and_source",true);
                    result.addProperty("rename_receipt_restart_read_only",true);
                    result.addProperty("ga13_receipt_before",receipt.beforeName());
                    result.addProperty("ga13_receipt_after",receipt.afterName());
                    result.addProperty("ga13_receipt_revision",
                        receipt.reviewedModification());
                    result.addProperty("ga13_receipt_source_sha",
                        receipt.sourceSha256());
                    result.addProperty("ga13_process_pid",
                        ProcessHandle.current().pid());
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
                            WordDataType.dataType);
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
                } else if("vbr-relocation".equals(ga18Mode)) {
                    // A synthetic CPU32 MOVEC D0,VBR sources 0x800. A separate
                    // table at 0x800 has an exact function-entry candidate,
                    // an interior pointer and an odd address; NONE is active
                    // IRQ/VBR execution evidence.
                    int vbrTx=full.startTransaction(
                        "GA11 isolated relocated table and MOVEC source");
                    try {
                        full.getMemory().setBytes(address(full,0x800L),
                            new byte[1024]);
                        full.getMemory().setBytes(address(full,0x868L),
                            java.util.HexFormat.of().parseHex("00000400"));
                        full.getMemory().setBytes(address(full,0x86cL),
                            java.util.HexFormat.of().parseHex("00000402"));
                        full.getMemory().setBytes(address(full,0x870L),
                            java.util.HexFormat.of().parseHex("00000401"));
                        full.getMemory().setBytes(address(full,0x874L),
                            java.util.HexFormat.of().parseHex("01000000"));
                        full.getMemory().setBytes(address(full,0x5a0L),
                            java.util.HexFormat.of().parseHex(
                                "203c000008004e7b08014e75"));
                    } finally {full.endTransaction(vbrTx,true);}
                    defineFixtureFunction(full,0x5a0L,12,
                        "fixture_relocated_vbr_source");
                    var movecInsn=full.getListing().getInstructionAt(
                        address(full,0x5a6L));
                    check(movecInsn!=null &&
                        movecInsn.toString().toUpperCase(Locale.ROOT)
                            .contains("VBR"),
                        "Ghidra CPU32 did not decode relocated MOVEC D0,VBR");
                    boolean genericRefused=false;
                    try {
                        GhidraInterruptVectorService.analyzeRelocatedSourceTables(
                            full,HardwareProfiles.cpu32Family(),TaskMonitor.DUMMY,
                            List.of(),0,true,false,Set.of(),List.of());
                    } catch(IllegalArgumentException expected) {
                        genericRefused=true;
                    }
                    check(genericRefused,
                        "Relocated service must refuse generic CPU32 without MC68332 profile");
                    long initialVbrRev=full.getModificationNumber();
                    var vbrReport=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true);
                    String md=vbrReport.markdown;
                    String baseTag="### Relocated **source-image** table "+
                        "candidate at 0x00000800";
                    check(md.contains(baseTag) &&
                        md.contains("runtime VBR UNKNOWN") &&
                        md.contains("STATIC SOURCE CANDIDATES ONLY"),
                        "Relocated byte table promoted to active hardware VBR");
                    String relocated=md.substring(md.indexOf(baseTag));
                    check(relocated.contains("relocated MOVEC-to-VBR "+
                            "source-image candidate at 0x00000800") &&
                        relocated.contains("| Vector | Relocated source-image pointer |") &&
                        relocated.contains("relocated source-image vector words") &&
                        !relocated.contains("Vector table input: image-zero bytes ONLY") &&
                        !relocated.contains("| Vector | Image-zero pointer |") &&
                        relocated.contains("runtime VBR and IRQ activation UNKNOWN"),
                        "Relocated real Program source vector mislabeled as image-zero");
                    check(relocated.contains("RECOGNIZED_FUNCTION_CANDIDATE") &&
                        relocated.contains(
                            "INTERIOR_FUNCTION_POINTER_CANDIDATE") &&
                        relocated.contains("ODD_POINTER") &&
                        relocated.contains("OUTSIDE_SELECTED_MCU24_RANGE") &&
                        relocated.contains("outside explicitly selected MCU24 width: 1") &&
                        md.contains(HardwareBitfieldSourceLedger.MC68332_PUBLIC_PDF_SHA256) &&
                        relocated.contains("pointers inside recognized "+
                            "function bodies (NOT entries): 1"),
                        "Actual relocated table bytes or function entry "+
                        "classification missing");
                    check(md.contains("Explicit device profile: MC68332") &&
                        md.contains("local RAG copies, runtime VBR and ISR remain UNKNOWN"),
                        "MC68332 source provenance must not authenticate local RAG files");
                    result.addProperty("ga06_ga11_explicit_device_rejects_generic",true);
                    result.addProperty("ga06_ga11_mcu24_out_of_range_source",true);
                    check(full.getModificationNumber()==initialVbrRev,
                        "Read-only VBR evidence analysis modified Program");
                    var genericVbr=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,false);
                    check(genericVbr.markdown.contains("Relocated VBR "+
                            "source-table candidates") &&
                        genericVbr.markdown.contains("Not evaluated: "+
                            "MC68332 profile not explicitly selected") &&
                        !genericVbr.markdown.contains(baseTag),
                        "Generic CPU32 accidentally inherited MC68332 "+
                        "relocated vector-table inference");
                    // The same programmed MOVEC is unchanged, but source
                    // vector data changes. No stale result may be reported.
                    int editVbr=full.startTransaction(
                        "GA11 isolated candidate vector rewrite");
                    try {
                        full.getMemory().setBytes(address(full,0x868L),
                            java.util.HexFormat.of().parseHex("00000402"));
                    } finally {full.endTransaction(editVbr,true);}
                    long updatedVbrRev=full.getModificationNumber();
                    String edited=new GhidraHardwareFlowService().analyze(
                        full,TaskMonitor.DUMMY,true).markdown;
                    String editedRelocated=edited.substring(
                        edited.indexOf(baseTag));
                    check(editedRelocated.contains("pointers inside recognized "+
                            "function bodies (NOT entries): 2") &&
                        full.getModificationNumber()==updatedVbrRev,
                        "Relocated table source edit was stale or wrote Program");
                    check(full.canUndo(),"Synthetic Ghidra vector Undo unavailable");
                    full.undo();
                    byte[] restoredVbr=new byte[4];
                    full.getMemory().getBytes(address(full,0x868L),
                        restoredVbr);
                    check(java.util.Arrays.equals(restoredVbr,
                        java.util.HexFormat.of().parseHex("00000400")),
                        "Undo did not restore relocated vector source bytes");
                    long restoredVbrRev=full.getModificationNumber();
                    String restoredReport=new GhidraHardwareFlowService()
                        .analyze(full,TaskMonitor.DUMMY,true).markdown;
                    check(restoredReport.substring(
                            restoredReport.indexOf(baseTag))
                            .contains("pointers inside recognized "+
                                "function bodies (NOT entries): 1") &&
                        full.getModificationNumber()==restoredVbrRev,
                        "Undo failed to restore read-only relocated evidence");
                    result.addProperty("vbr_relocation_real_movec_decoded",true);
                    result.addProperty("vbr_relocation_exact_and_interior",true);
                    result.addProperty("vbr_relocation_edit_invalidates",true);
                    result.addProperty("vbr_relocation_undo_restores",true);
                    result.addProperty(
                        "vbr_relocation_generic_cpu32_not_device_profile",true);
                    result.addProperty("vbr_relocation_read_only",true);
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
