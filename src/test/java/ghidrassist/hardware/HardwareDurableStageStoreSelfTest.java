package ghidrassist.hardware;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Arrays;
import static ghidrassist.hardware.HardwareDurableStageStore.*;

public final class HardwareDurableStageStoreSelfTest {
    private HardwareDurableStageStoreSelfTest(){}
    private static void ok(boolean b,String why){if(!b)throw new AssertionError(why);}
    /** Synthetic source can grow forever after an optimistic size check. */
    private static final class EndlessSource extends java.io.InputStream {
        int consumed;
        @Override public int read() {
            consumed++;return 0;
        }
        @Override public int read(byte[] bytes,int offset,int length) {
            Arrays.fill(bytes,offset,offset+length,(byte)0);
            consumed+=length;
            return length;
        }
    }
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
            ok(Arrays.equals(decodeBounded(
                    new java.io.ByteArrayInputStream(Files.readAllBytes(
                        checkpointPath(dir,identity))),identity).orElseThrow(),data),
                "bounded stream decode preserves exact existing checkpoint content");
            // GA-12: a second full-source fingerprint must be compared to
            // the source captured BEFORE the analysis, never replace it.
            // Every variant retains the same disk slot when project ID
            // matches, but must not overwrite the legitimate prior proof.
            var recreatedKey=new Key(project,original,input,code,
                "68000:BE:32:CPU32",true);
            ok(saveIfSameSource(dir,identity,recreatedKey,data) &&
                Arrays.equals(load(dir,identity).orElseThrow(),data),
                "same complete pre/post-analysis source permits publication");
            byte[] trustedBytes=Files.readAllBytes(checkpointPath(dir,identity));
            byte[] otherStage="forged report from another source".getBytes(
                StandardCharsets.UTF_8);
            var staleInputs=java.util.Arrays.asList(
                new Key(project,original,hash("edited Listing"),code,
                    "68000:BE:32:CPU32",true),
                new Key(project,hash("changed import"),input,code,
                    "68000:BE:32:CPU32",true),
                new Key(project,original,input,hash("changed engine"),
                    "68000:BE:32:CPU32",true),
                new Key(project,original,input,code,"OTHER",true),
                new Key(project,original,input,code,
                    "68000:BE:32:CPU32",false),
                new Key(hash("other project"),original,input,code,
                    "68000:BE:32:CPU32",true));
            for(var changed:staleInputs){
                ok(!saveIfSameSource(dir,identity,changed,otherStage) &&
                    !saveIfSameSource(dir,changed,identity,otherStage) &&
                    Arrays.equals(Files.readAllBytes(
                        checkpointPath(dir,identity)),trustedBytes),
                    "pre/post source drift must never overwrite a proven checkpoint");
            }
            ok(!saveIfSameSource(dir,null,identity,otherStage) &&
                !saveIfSameSource(dir,identity,null,otherStage) &&
                Arrays.equals(Files.readAllBytes(
                    checkpointPath(dir,identity)),trustedBytes),
                "missing first capture or failed second capture never publishes");
            ok(Arrays.equals(load(dir,identity).orElseThrow(),data),
                "rejected replay publication preserves genuine existing evidence");
            // Tiny read chunks still form a valid record; no readAllBytes needed.
            byte[] exact=Files.readAllBytes(checkpointPath(dir,identity));
            var chunked=new java.io.ByteArrayInputStream(exact){
                @Override public synchronized int read(byte[] bytes,int off,int len){
                    return super.read(bytes,off,Math.min(7,len));
                }
            };
            ok(Arrays.equals(decodeBounded(chunked,identity).orElseThrow(),data),
                "partial InputStream reads do not corrupt checkpoint decode");
            var endless=new EndlessSource();
            ok(decodeBounded(endless,identity).isEmpty() &&
                endless.consumed==MAX_FILE_BYTES+1,
                "file growth after stat cannot cause an unbounded read");
            ok(decodeBounded(null,identity).isEmpty() &&
                decodeBounded(new java.io.ByteArrayInputStream(exact),null).isEmpty(),
                "missing stream/key must remain a cache miss");

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
            // Sparse oversized file: metadata guard rejects it before
            // allocating its apparent length. Restoring exact bytes works.
            try(java.io.RandomAccessFile oversized=
                    new java.io.RandomAccessFile(file.toFile(),"rw")){
                oversized.setLength(MAX_FILE_BYTES+100L);
            }
            ok(load(dir,identity).isEmpty(),
                "oversized on-disk checkpoint refuses to load");
            Files.write(file,correct);
            ok(Arrays.equals(load(dir,identity).orElseThrow(),data),
                "oversized rejection cannot poison future valid loads");
            // A group/world-writable cache directory permits another
            // account to replace the report and its unkeyed checksum.
            // This is an opt-in local cache, not a trusted actor journal.
            if(Files.getFileStore(dir).supportsFileAttributeView("posix")) {
                var originalMode=Files.getPosixFilePermissions(dir);
                var restoredMode=Files.getPosixFilePermissions(file);
                try {
                    var shared=new java.util.HashSet<>(originalMode);
                    shared.add(java.nio.file.attribute.PosixFilePermission.GROUP_WRITE);
                    Files.setPosixFilePermissions(dir,shared);
                    refused=false;
                    try{save(dir,identity,data);}catch(IOException expected){
                        refused=true;
                    }
                    ok(refused && load(dir,identity).isEmpty(),
                        "group-writable checkpoint directory rejects save AND restore");
                    shared.remove(java.nio.file.attribute.PosixFilePermission.GROUP_WRITE);
                    shared.add(java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE);
                    Files.setPosixFilePermissions(dir,shared);
                    refused=false;
                    try{save(dir,identity,data);}catch(IOException expected){
                        refused=true;
                    }
                    ok(refused && load(dir,identity).isEmpty(),
                        "other-writable cache directory never authenticates SHA record");
                }finally{
                    Files.setPosixFilePermissions(dir,originalMode);
                }
                ok(Arrays.equals(load(dir,identity).orElseThrow(),data),
                    "restored private directory permits unchanged valid checkpoint");
                try {
                    var sharedFile=new java.util.HashSet<>(restoredMode);
                    sharedFile.add(
                        java.nio.file.attribute.PosixFilePermission.GROUP_WRITE);
                    Files.setPosixFilePermissions(file,sharedFile);
                    ok(load(dir,identity).isEmpty(),
                        "group-writable checkpoint file rejected before decode");
                    sharedFile.remove(
                        java.nio.file.attribute.PosixFilePermission.GROUP_WRITE);
                    sharedFile.add(
                        java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE);
                    Files.setPosixFilePermissions(file,sharedFile);
                    ok(load(dir,identity).isEmpty(),
                        "world-writable checkpoint file rejected");
                }finally{
                    Files.setPosixFilePermissions(file,restoredMode);
                }
                ok(Arrays.equals(load(dir,identity).orElseThrow(),data),
                    "owner-only checkpoint file remains restorable after safety tests");
            }
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
