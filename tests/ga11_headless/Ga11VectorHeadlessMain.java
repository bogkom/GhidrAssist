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
import ghidrassist.hardware.GhidraInterruptVectorService;
import ghidrassist.hardware.GhidraHardwareFlowService;
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
    public static void main(String[] args)throws Exception {
        Path ghidra=Path.of(args[0]).toRealPath();
        Path projectDir=Path.of(args[1]).toRealPath();
        Path out=Path.of(args[2]).toRealPath();
        boolean strictEntry=Boolean.parseBoolean(args[3]);
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
