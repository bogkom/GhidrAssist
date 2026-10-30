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
        check(Set.of("none","overview","cache","startup","csbar","revision").contains(ga18Mode),
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
