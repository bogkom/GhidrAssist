// Verify late rollback after the preceding GhidraScript transaction has closed.
// Disposable ga08-synthetic.bin only; invokes the built production extension.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.lang.reflect.Method;
import java.util.List;

public class GA08VerifyProductionApplyAfterTransaction extends GhidraScript {
    private void require(boolean ok, String message) {
        if (!ok) throw new IllegalStateException("GA08 FAIL: " + message);
    }
    @Override public void run() throws Exception {
        String path=System.getProperty("ga08.test.jar");
        require(path!=null && new File(path).isFile(), "production JAR missing");
        require(currentProgram!=null && "ga08-synthetic.bin".equals(currentProgram.getName()),
                "refuse non-disposable program");
        try (URLClassLoader loader=new URLClassLoader(
                new URL[]{new File(path).toURI().toURL()},
                ghidra.program.model.listing.Program.class.getClassLoader())) {
            Class<?> plan=Class.forName("ghidrassist.hardware.HardwareApplyPlan",true,loader);
            Class<?> itemType=Class.forName("ghidrassist.hardware.HardwareApplyPlan$Item",true,loader);
            Class<?> service=Class.forName("ghidrassist.hardware.HardwareApplyService",true,loader);
            Method apply=service.getMethod("apply",
                    ghidra.program.model.listing.Program.class,List.class);
            List<?> items=(List<?>)plan.getMethod("mc68332Mm1Candidates",long.class)
                    .invoke(null,0x1000L);
            Object first=items.stream().filter(item -> {
                try {
                    return itemType.getField("kind").get(item).toString().equals("MEMORY")
                        && !itemType.getField("name").get(item).equals("TPURAM_2K_CANDIDATE");
                } catch(Exception ex){throw new IllegalStateException(ex);}
            }).findFirst().orElseThrow();
            long offset=itemType.getField("address").getLong(first);
            int length=itemType.getField("length").getInt(first);
            String name=(String)itemType.getField("name").get(first);
            var at=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
            require(currentProgram.getMemory().getBlock(at)==null,
                    "first MEMORY block survived late transaction rollback");
            println("GA08 PRODUCTION APPLY LATE ROLLBACK PASS: prior_mutations=1 surviving=0");
            Object outcome=apply.invoke(null,currentProgram,List.of(first));
            require(outcome.getClass().getField("changed").getInt(outcome)==1,
                    "positive Apply must change one region");
            MemoryBlock block=currentProgram.getMemory().getBlock(at);
            require(block!=null && block.getSize()==length && block.getName().equals(name),
                    "positive Apply region mismatch");
            Object again=apply.invoke(null,currentProgram,List.of(first));
            require(again.getClass().getField("changed").getInt(again)==0,
                    "idempotent Apply changed project");
            require(again.getClass().getField("skipped").getInt(again)==1,
                    "idempotent Apply did not skip");
            println("GA08 PRODUCTION APPLY POSITIVE PASS: changed=1 idempotent_skip=1");
        }
    }
}
