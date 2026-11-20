// Establish independent user-owned controls in a completed GhidraScript transaction.
// Must run BEFORE the failure-injection script so its rollback cannot erase fixtures.
import ghidra.app.script.GhidraScript;
import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.List;
public class GA08SetupProductionApplyFixture extends GhidraScript {
 @Override public void run() throws Exception {
  if(currentProgram==null || !"ga08-synthetic.bin".equals(currentProgram.getName())) throw new IllegalStateException("GA08 FAIL: refuse non-disposable fixture");
  String path=System.getProperty("ga08.test.jar");
  if(path==null || !new File(path).isFile()) throw new IllegalStateException("GA08 FAIL: production JAR missing");
  try(URLClassLoader loader=new URLClassLoader(new URL[]{new File(path).toURI().toURL()},ghidra.program.model.listing.Program.class.getClassLoader())) {
   Class<?> plan=Class.forName("ghidrassist.hardware.HardwareApplyPlan",true,loader);
   Class<?> itemType=Class.forName("ghidrassist.hardware.HardwareApplyPlan$Item",true,loader);
   List<?> items=(List<?>)plan.getMethod("mc68332Mm1Candidates",long.class).invoke(null,0x1000L);
   Object first=items.stream().filter(item->{try{return itemType.getField("kind").get(item).toString().equals("MEMORY") && !itemType.getField("name").get(item).equals("TPURAM_2K_CANDIDATE");}catch(Exception e){throw new IllegalStateException(e);}}).findFirst().orElseThrow();
   long address=itemType.getField("address").getLong(first);
   Object second=items.stream().filter(item->{try{return itemType.getField("kind").get(item).toString().equals("MEMORY") && itemType.getField("address").getLong(item)!=address && !itemType.getField("name").get(item).equals("TPURAM_2K_CANDIDATE");}catch(Exception e){throw new IllegalStateException(e);}}).findFirst().orElseThrow();
   long other=itemType.getField("address").getLong(second);
   var otherAt=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(other);
   Object exact=items.stream().filter(item->{try{return itemType.getField("kind").get(item).toString().equals("MEMORY") && itemType.getField("address").getLong(item)!=address && itemType.getField("address").getLong(item)!=other && !itemType.getField("name").get(item).equals("TPURAM_2K_CANDIDATE");}catch(Exception e){throw new IllegalStateException(e);}}).findFirst().orElseThrow();
   long exactOffset=itemType.getField("address").getLong(exact);
   int exactLength=itemType.getField("length").getInt(exact);
   var exactAt=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(exactOffset);
   if(currentProgram.getMemory().getBlock(otherAt)!=null || currentProgram.getMemory().getBlock(exactAt)!=null) throw new IllegalStateException("GA08 FAIL: fixture already mapped");
   int tx=currentProgram.startTransaction("GA08 independent fixture setup");
   boolean commit=false;
   try {
    var conflictBlock=currentProgram.getMemory().createUninitializedBlock("GA08_USER_CONFLICT",otherAt,1,false);
    var exactBlock=currentProgram.getMemory().createUninitializedBlock("GA08_USER_EXACT",exactAt,exactLength,false);
    // Ghidra does not guarantee the default access flags of newly created
    // uninitialized blocks. Make the two independent user controls explicit.
    for (var block : new ghidra.program.model.mem.MemoryBlock[]{conflictBlock, exactBlock}) {
     block.setRead(true);
     block.setWrite(true);
     block.setExecute(false);
    }
    commit=true;
   } finally {currentProgram.endTransaction(tx,commit);}
   println("GA08 INDEPENDENT FIXTURE SETUP PASS: conflict=1 exact=1");
  }
 }
}
