package ghidrassist.hardware;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.Optional;

/**
 * A conservative opt-in fingerprint of everything used by the current
 * CFG/Listing evidence pass. Fail closed when full inspection is too large.
 *
 * Original import SHA alone is never a valid restart checkpoint key:
 * disassembly, function bodies, references or symbol names may change.
 */
public final class HardwareGhidraInputFingerprint {
    private HardwareGhidraInputFingerprint(){}
    private static final long MAX_INITIALIZED_BYTES=64L*1024L*1024L;
    private static final int MAX_INSTRUCTIONS=1_000_000;
    private static final int MAX_FUNCTIONS=100_000;
    private static final String SNAPSHOT_ENGINE="GHIDRASSIST-GA12-CFG-SNAPSHOT-1";

    private static MessageDigest digest(){
        try{return MessageDigest.getInstance("SHA-256");}
        catch(NoSuchAlgorithmException e){throw new AssertionError(e);}
    }
    private static void string(MessageDigest md,String value){
        byte[] text=(value==null?"<null>":value).getBytes(StandardCharsets.UTF_8);
        int length=text.length;
        md.update(new byte[] {(byte)(length>>>24),(byte)(length>>>16),
            (byte)(length>>>8),(byte)length});
        md.update(text);
    }
    private static void offset(MessageDigest md,long number){
        string(md,Long.toUnsignedString(number));
    }
    private static String hex(MessageDigest md){
        return java.util.HexFormat.of().formatHex(md.digest());
    }

    /** Returns empty if any input cannot be inspected consistently. */
    public static Optional<HardwareDurableStageStore.Key> capture(
            Program program,TaskMonitor monitor,boolean mc68332)
            throws CancelledException {
        if(program==null || monitor==null)return Optional.empty();
        long before=program.getModificationNumber();
        try {
            if(program.getDomainFile()==null ||
                    program.getDomainFile().getFileID()==null ||
                    program.getDomainFile().getProjectLocator()==null ||
                    program.getExecutableSHA256()==null ||
                    !program.getExecutableSHA256().matches("(?i)[0-9a-f]{64}"))
                return Optional.empty();
            String source=program.getExecutableSHA256().toLowerCase(Locale.ROOT);
            MessageDigest identity=digest();
            string(identity,program.getDomainFile().getFileID());
            string(identity,program.getDomainFile().getProjectLocator().toString());
            string(identity,program.getDomainFile().getPathname());
            String projectId=hex(identity);

            // Bind a persisted report to the exact installed extension JAR,
            // not just an unbumped human-maintained algorithm version.
            var protection=GhidraHardwareFlowService.class.getProtectionDomain();
            if(protection==null || protection.getCodeSource()==null)
                return Optional.empty();
            Path jar=Path.of(protection.getCodeSource().getLocation().toURI());
            if(!Files.isRegularFile(jar) || Files.size(jar)>128L*1024L*1024L)
                return Optional.empty();
            MessageDigest engine=digest();
            string(engine,SNAPSHOT_ENGINE);
            try(var input=Files.newInputStream(jar)){
                byte[] buffer=new byte[65536];
                int n;
                while((n=input.read(buffer))!=-1){
                    monitor.checkCancelled();
                    engine.update(buffer,0,n);
                }
            }
            String analyzerSha=hex(engine);

            MessageDigest contents=digest();
            string(contents,SNAPSHOT_ENGINE);
            string(contents,program.getLanguageID().toString());
            string(contents,program.getCompilerSpec().getCompilerSpecID().toString());
            string(contents,source);
            offset(contents,before);
            MemoryBlock[] blocks=program.getMemory().getBlocks();
            offset(contents,blocks.length);
            long bytes=0;
            byte[] buffer=new byte[65536];
            for(MemoryBlock block:blocks){
                monitor.checkCancelled();
                string(contents,block.getName());
                string(contents,block.getStart().toString());
                string(contents,block.getEnd().toString());
                string(contents,Boolean.toString(block.isInitialized()));
                string(contents,Boolean.toString(block.isRead()));
                string(contents,Boolean.toString(block.isWrite()));
                string(contents,Boolean.toString(block.isExecute()));
                if(!block.isInitialized())continue;
                long size=block.getSize();
                if(size<0 || size>MAX_INITIALIZED_BYTES-bytes)
                    return Optional.empty();
                bytes+=size;
                for(long i=0;i<size;){
                    monitor.checkCancelled();
                    int requested=(int)Math.min(buffer.length,size-i);
                    Address at=block.getStart().add(i);
                    int count=program.getMemory().getBytes(at,buffer,0,requested);
                    if(count!=requested)return Optional.empty();
                    contents.update(buffer,0,count);
                    i+=count;
                }
            }

            FunctionIterator functions=program.getFunctionManager().getFunctions(true);
            int functionCount=0,instructionCount=0;
            while(functions.hasNext()){
                monitor.checkCancelled();
                if(++functionCount>MAX_FUNCTIONS)return Optional.empty();
                Function function=functions.next();
                string(contents,function.getEntryPoint().toString());
                string(contents,function.getName());
                offset(contents,function.getBody().getNumAddresses());
                InstructionIterator instructions=
                    program.getListing().getInstructions(function.getBody(),true);
                while(instructions.hasNext()){
                    monitor.checkCancelled();
                    if(++instructionCount>MAX_INSTRUCTIONS)return Optional.empty();
                    Instruction insn=instructions.next();
                    string(contents,insn.getAddress().toString());
                    string(contents,insn.getMnemonicString());
                    offset(contents,insn.getLength());
                    string(contents,insn.getFlowType().toString());
                    string(contents,String.valueOf(insn.getFallThrough()));
                    for(Address target:insn.getFlows())
                        string(contents,target.toString());
                    string(contents,"END_FLOWS");
                    for(int i=0;i<insn.getNumOperands();i++)
                        string(contents,insn.getDefaultOperandRepresentation(i));
                    string(contents,"END_OPERANDS");
                    PcodeOp[] ops=insn.getPcode();
                    if(ops!=null)for(PcodeOp op:ops)
                        string(contents,op.toString());
                    string(contents,"END_PCODE");
                    for(Reference reference:insn.getReferencesFrom()){
                        string(contents,reference.getFromAddress().toString());
                        string(contents,reference.getToAddress().toString());
                        string(contents,reference.getReferenceType().toString());
                    }
                    string(contents,"END_INSN_REFS");
                }
                string(contents,"END_FUNCTION_BODY");
                ReferenceIterator refs=program.getReferenceManager()
                    .getReferencesTo(function.getEntryPoint());
                while(refs.hasNext()){
                    monitor.checkCancelled();
                    Reference reference=refs.next();
                    string(contents,reference.getFromAddress().toString());
                    string(contents,reference.getToAddress().toString());
                    string(contents,reference.getReferenceType().toString());
                }
                string(contents,"END_FUNCTION_REFS");
            }
            offset(contents,functionCount);
            offset(contents,instructionCount);
            if(program.getModificationNumber()!=before)return Optional.empty();
            return Optional.of(new HardwareDurableStageStore.Key(
                projectId,source,hex(contents),analyzerSha,
                program.getLanguageID().toString(),mc68332));
        }catch(IOException|RuntimeException|java.net.URISyntaxException|
                MemoryAccessException unreadable){
            return Optional.empty();
        }
    }
}
