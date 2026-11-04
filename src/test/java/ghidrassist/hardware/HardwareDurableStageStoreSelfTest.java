package ghidrassist.hardware;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Arrays;
import static ghidrassist.hardware.HardwareDurableStageStore.*;

public final class HardwareDurableStageStoreSelfTest {
    private HardwareDurableStageStoreSelfTest(){}
    private static void ok(boolean b,String why){if(!b)throw new AssertionError(why);}
    public static void main(String[] args)throws Exception {
        Path dir=Files.createTempDirectory("ga12-durable-synthetic-");
        try{
            String project=hash("isolated-project-id");
            String original=hash("synthetic-import-bytes");
            String input=hash("entire-program-analysis-state-v1");
            String code=hash("GhidrAssist-algorithm-v1");
            var identity=new Key(project,original,input,code,
                "68000:BE:32:CPU32",true);
            var data="read-only synthetic completed CFG evidence".getBytes(
                StandardCharsets.UTF_8);
            ok(load(dir,identity).isEmpty(),"fresh project is a cache miss");
            save(dir,identity,data);
            ok(Arrays.equals(load(dir,identity).orElseThrow(),data),
                "durable checkpoint survives independent disk load");
            ok(load(dir,new Key(project,original,
                hash("same-import-but-modified-ghidra-listing"),code,
                "68000:BE:32:CPU32",true)).isEmpty(),
                "Ghidra analysis edits reject stale import-SHA-only match");
            ok(load(dir,new Key(project,original,input,
                hash("new-extension-bytecode"),"68000:BE:32:CPU32",true)).isEmpty(),
                "changed analysis engine cannot reuse previous findings");
            ok(load(dir,new Key(project,original,input,code,
                "68000:BE:32:CPU32",false)).isEmpty(),
                "different MCU selection cannot reuse checkpoint");
            ok(load(dir,new Key(hash("another-project"),original,input,code,
                "68000:BE:32:CPU32",true)).isEmpty(),
                "same firmware from different project cannot cross-reuse");
            ok(load(dir,new Key(project,original,input,code,
                "OTHER",true)).isEmpty(),"language mismatch fails closed");
            Path file=checkpointPath(dir,identity);
            byte[] correct=Files.readAllBytes(file);
            byte[] damaged=correct.clone();
            damaged[damaged.length-40]^=0x7f;
            Files.write(file,damaged);
            ok(load(dir,identity).isEmpty(),"tampered digest is a miss");
            Files.write(file,Arrays.copyOf(correct,correct.length-5));
            ok(load(dir,identity).isEmpty(),"truncated file is a miss");
            Files.write(file,correct);
            ok(Arrays.equals(load(dir,identity).orElseThrow(),data),
                "unchanged stage restored after rejected corrupt snapshots");
            boolean refused=false;
            try{save(dir,identity,new byte[MAX_PAYLOAD_BYTES+1]);}
            catch(IllegalArgumentException e){refused=true;}
            ok(refused,"oversized stage rejected");
            refused=false;
            try{new Key(project,original,original,code,"",true);}
            catch(IllegalArgumentException e){refused=true;}
            ok(refused,"empty analysis language rejected");
            // A hostile redirect cannot trick checkpoint writes.
            Files.delete(file);
            Path outside=Files.createTempFile("ga12-other",".bin");
            Files.writeString(outside,"do not alter");
            try{
                Files.createSymbolicLink(file,outside);
                refused=false;
                try{save(dir,identity,data);}
                catch(IOException e){refused=true;}
                ok(refused && Files.readString(outside).equals("do not alter") &&
                    load(dir,identity).isEmpty(),
                    "symbolic-link destination never read/written");
            }finally{Files.deleteIfExists(file);Files.deleteIfExists(outside);}
            System.out.println("HardwareDurableStageStoreSelfTest OK");
        }finally{
            try(var stream=Files.list(dir)){
                for(Path p:stream.toList())Files.deleteIfExists(p);
            }
            Files.delete(dir);
        }
    }
}
