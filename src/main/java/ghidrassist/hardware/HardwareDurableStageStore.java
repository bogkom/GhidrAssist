package ghidrassist.hardware;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Optional;
import static java.nio.file.LinkOption.NOFOLLOW_LINKS;

/**
 * GA-12 durable, fail-closed, opt-in completed-stage byte storage.
 * Only a caller-supplied SHA-256 of the FULL current analysis input is
 * eligible: original firmware SHA and Ghidra modification number alone
 * never authenticate the current Listing after a Ghidra restart.
 */
public final class HardwareDurableStageStore {
    private HardwareDurableStageStore(){}
    public static final String SCHEMA="GA12-CFG-DISK-1";
    public static final int MAX_PAYLOAD_BYTES=4*1024*1024;
    private static final int MAX_FILE_BYTES=MAX_PAYLOAD_BYTES+4096;
    private static final int MAX_HEADER_BYTES=2048;
    private static final int MAGIC=0x47413132;

    public record Key(String programIdSha256,String importedSha256,
                      String inputSha256,String analyzerSha256,
                      String language,boolean mc68332) {
        public Key {
            if(!hex(programIdSha256)||!hex(importedSha256)||
                    !hex(inputSha256)||!hex(analyzerSha256)||
                    language==null || language.isBlank() || language.length()>128)
                throw new IllegalArgumentException("Weak durable checkpoint key");
        }
    }
    private static boolean hex(String s){return s!=null && s.matches("[a-f0-9]{64}");}
    private static byte[] sha(byte[] bytes){
        try{return MessageDigest.getInstance("SHA-256").digest(bytes);}
        catch(NoSuchAlgorithmException e){throw new AssertionError(e);}
    }
    public static String hash(byte[] data){
        return java.util.HexFormat.of().formatHex(sha(data));
    }
    public static String hash(String data){
        return hash(data.getBytes(StandardCharsets.UTF_8));
    }
    public static Path checkpointPath(Path directory,Key key){
        if(directory==null || key==null)
            throw new IllegalArgumentException("Missing checkpoint path/key");
        return directory.resolve("ga12-"+key.programIdSha256()+".chk");
    }
    private static void checkDirectory(Path dir)throws IOException{
        if(dir==null || Files.isSymbolicLink(dir) ||
                !Files.isDirectory(dir,NOFOLLOW_LINKS))
            throw new IOException("Checkpoint directory missing or unsafe");
    }
    public static void save(Path directory,Key key,byte[] stage)
            throws IOException{
        checkDirectory(directory);
        if(key==null || stage==null || stage.length==0 ||
                stage.length>MAX_PAYLOAD_BYTES)
            throw new IllegalArgumentException("Invalid complete-stage payload");
        Path target=checkpointPath(directory,key);
        if(Files.isSymbolicLink(target))
            throw new IOException("Refusing symlink checkpoint destination");
        ByteArrayOutputStream body=new ByteArrayOutputStream();
        try(DataOutputStream out=new DataOutputStream(body)){
            out.writeInt(MAGIC);
            out.writeUTF(SCHEMA);
            out.writeUTF(key.programIdSha256());
            out.writeUTF(key.importedSha256());
            out.writeUTF(key.inputSha256());
            out.writeUTF(key.analyzerSha256());
            out.writeUTF(key.language());
            out.writeBoolean(key.mc68332());
            out.writeInt(stage.length);
            out.write(stage);
        }
        byte[] headerAndBody=body.toByteArray();
        if(headerAndBody.length>MAX_FILE_BYTES-32)
            throw new IllegalArgumentException("Checkpoint too large");
        Path temp=Files.createTempFile(directory,"ga12-",".tmp");
        try{
            try{
                Files.setPosixFilePermissions(temp,
                    EnumSet.of(PosixFilePermission.OWNER_READ,
                               PosixFilePermission.OWNER_WRITE));
            }catch(UnsupportedOperationException ignored){}
            try(OutputStream output=Files.newOutputStream(temp,
                    StandardOpenOption.WRITE,StandardOpenOption.TRUNCATE_EXISTING)){
                output.write(headerAndBody);
                output.write(sha(headerAndBody));
            }
            Files.move(temp,target,StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING);
        }finally{
            Files.deleteIfExists(temp);
        }
    }
    /** Corrupt, stale, foreign or incomplete files are a cache miss. */
    public static Optional<byte[]> load(Path directory,Key key){
        if(key==null)return Optional.empty();
        try{
            checkDirectory(directory);
            Path path=checkpointPath(directory,key);
            if(!Files.isRegularFile(path,NOFOLLOW_LINKS) ||
                    Files.size(path)>MAX_FILE_BYTES ||
                    Files.size(path)<32+MAX_HEADER_BYTES/20)
                return Optional.empty();
            byte[] bytes=Files.readAllBytes(path);
            byte[] body=Arrays.copyOf(bytes,bytes.length-32);
            if(!MessageDigest.isEqual(sha(body),
                    Arrays.copyOfRange(bytes,bytes.length-32,bytes.length)))
                return Optional.empty();
            try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(body))){
                if(in.readInt()!=MAGIC || !SCHEMA.equals(in.readUTF()) ||
                        !key.programIdSha256().equals(in.readUTF()) ||
                        !key.importedSha256().equals(in.readUTF()) ||
                        !key.inputSha256().equals(in.readUTF()) ||
                        !key.analyzerSha256().equals(in.readUTF()) ||
                        !key.language().equals(in.readUTF()) ||
                        key.mc68332()!=in.readBoolean())
                    return Optional.empty();
                int size=in.readInt();
                if(size<=0 || size>MAX_PAYLOAD_BYTES ||
                        size!=in.available())return Optional.empty();
                return Optional.of(in.readNBytes(size));
            }
        }catch(IOException|RuntimeException bad){
            return Optional.empty();
        }
    }
}
