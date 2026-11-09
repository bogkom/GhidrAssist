// @category GhidrAssist.Tests
// Production flow service + image-zero candidates on generated CPU32 ONLY.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;

public class GA18VerifyVectorResetCorrelation extends GhidraScript {
    private int assertions;
    private void check(boolean value, String explanation) {
        assertions++;
        if(!value)throw new IllegalStateException("GA18 VECTOR RESET FAIL: "+explanation);
    }
    @Override protected void run() throws Exception {
        if(currentProgram==null ||
                !"synthetic-callgraph.bin".equals(currentProgram.getName()))
            throw new IllegalStateException("Synthetic callgraph fixture only");
        check("68000:BE:32:CPU32".equals(currentProgram.getLanguageID().toString()),
            "CPU32 language");
        String jar=System.getProperty("ga18.test.jar","");
        if(jar.isBlank())throw new IllegalStateException("Missing tested extension jar");
        // An artifact-jar URLClassLoader is not Ghidra's extension loader.
        // The dynamic script host exposes different Ghidra module classes
        // through different owning loaders. Delegate to those actual defining
        // loaders, rather than packaging duplicate Ghidra classes into the jar.
        final ClassLoader[] ghidraLoaders={
            ghidra.program.model.pcode.PcodeOp.class.getClassLoader(),
            ghidra.program.model.listing.Program.class.getClassLoader(),
            ghidra.program.model.lang.Register.class.getClassLoader(),
            ghidra.program.model.mem.MemoryAccessException.class.getClassLoader(),
            ghidra.program.model.address.Address.class.getClassLoader(),
            ghidra.program.model.scalar.Scalar.class.getClassLoader(),
            ghidra.program.model.symbol.Reference.class.getClassLoader(),
            ghidra.util.exception.CancelledException.class.getClassLoader(),
            ghidra.util.task.TaskMonitor.class.getClassLoader(),
            ghidra.app.script.GhidraScript.class.getClassLoader()
        };
        ClassLoader bridge=new ClassLoader(getClass().getClassLoader()) {
            @Override protected Class<?> loadClass(String name, boolean resolve)
                    throws ClassNotFoundException {
                if(name.startsWith("ghidra.")) {
                    for(ClassLoader source:ghidraLoaders) {
                        if(source==null)continue;
                        try{return source.loadClass(name);}
                        catch(ClassNotFoundException notInModule) {
                            // Try the next actual Ghidra module loader.
                        }
                    }
                }
                return super.loadClass(name,resolve);
            }
        };
        try(URLClassLoader loader=new URLClassLoader(
                new URL[]{Path.of(jar).toUri().toURL()},bridge)) {
            Class<?> service=Class.forName(
                "ghidrassist.hardware.GhidraHardwareFlowService",true,loader);
            Object instance=service.getConstructor().newInstance();
            Method analyze=service.getMethod("analyze",Program.class,
                TaskMonitor.class,boolean.class);
            Object report=analyze.invoke(instance,currentProgram,monitor,false);
            Field markdown=report.getClass().getField("markdown");
            String text=(String)markdown.get(report);
            String title="## Vector / RESET static-call relation candidates";
            check(text.contains(title),"production report has correlation section");
            String sub=text.substring(text.indexOf(title));
            check(sub.contains("shared with observed RESET direct-call subset: 1"),
                "one exact vector target in bounded reset-call subset");
            check(sub.contains("not observed in that bounded subset: 1"),
                "one disconnected exact entry remains outside observed reset subset");
            check(sub.contains("interior pointers (NOT function entries): 1"),
                "interior function pointer never promoted to handler entry");
            check(sub.contains("| 26 | 0x00000130 | 0x00000130 | IN_RESET_STATIC_CALL_SUBSET"),
                "image-zero vector 26 exact reset-call candidate");
            check(sub.contains("| 32 | 0x00000220 | 0x00000220 | OUTSIDE_OBSERVED_RESET_SUBSET"),
                "image-zero vector 32 exact disconnected candidate");
            check(sub.contains("| 33 | 0x00000222 | 0x00000220 | INTERIOR_FUNCTION_POINTER_NOT_ENTRY"),
                "image-zero vector 33 interior candidate");
            check(sub.contains("STATIC ONLY") && sub.contains("runtime VBR"),
                "static evidence cannot claim active ISR or VBR");
            // The SAME real synthetic CPU32 Ghidra Program must refuse
            // MCU-specific MM/VBR conclusions without explicit device
            // selection; selecting MC68332 enables only the new read-only
            // source co-location section, never runtime claims or Apply.
            String joinTitle="## RESET / indirect MMIO / VBR source co-location";
            if(!text.contains(joinTitle) ||
                    !text.contains("Not evaluated: explicit MC68332 profile required"))
                throw new IllegalStateException(
                    "GA18 RESET-MM-VBR FAIL: generic CPU32 device gate");
            Object selectedReport=analyze.invoke(instance,currentProgram,monitor,true);
            String selectedText=(String)markdown.get(selectedReport);
            if(!selectedText.contains(joinTitle) ||
                    !selectedText.contains("STATIC SAME-FUNCTION SOURCE CO-LOCATION ONLY") ||
                    !selectedText.contains("NOT proof of absent indirect MMIO or VBR") ||
                    !selectedText.contains("selected VBR"))
                throw new IllegalStateException(
                    "GA18 RESET-MM-VBR FAIL: selected MC68332 bounded static report");
            println("GA18 RESET INDIRECT MM VBR PASS: selected-device gate, "+
                "bounded same-Program evidence, no hardware execution claim");
        }
        println("GA18 VECTOR RESET CORRELATION PASS: assertions="+assertions+
            " (real 12.1.4 headless; synthetic vector bytes; static only)");
    }
}
