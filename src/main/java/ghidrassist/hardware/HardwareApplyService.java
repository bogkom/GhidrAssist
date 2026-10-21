package ghidrassist.hardware;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import java.util.ArrayList;
import java.util.List;

/**
 * An EXPLICIT user-approved edit to the Ghidra Program DB. Every operation
 * occurs inside ONE undoable transaction, never in hardware-analysis scanning.
 * Blocks are UNINITIALIZED; no ROM bytes, existing instructions, data or
 * user labels are erased/overwritten.
 */
public final class HardwareApplyService {
    private HardwareApplyService(){}
    public static final class Outcome {
        public final int changed, skipped;
        public final List<String> messages;
        Outcome(int changed,int skipped,List<String> messages){
            this.changed=changed;this.skipped=skipped;this.messages=List.copyOf(messages);
        }
    }
    private static Address address(Program p,long offset){
        return p.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }
    private static boolean anyOverlap(Memory memory,Address start,Address end){
        for(MemoryBlock block:memory.getBlocks())
            if(block.getStart().getAddressSpace().equals(start.getAddressSpace()) &&
                    block.getStart().compareTo(end)<=0 &&
                    block.getEnd().compareTo(start)>=0)return true;
        return false;
    }
    private static boolean covers(Memory m,Address start,Address end){
        return m.contains(start)&&m.contains(end) &&
            m.getBlock(start)==m.getBlock(end);
    }
    private static boolean createBlock(Program p,HardwareApplyPlan.Item item,
                                       List<String> notes)throws Exception{
        Memory m=p.getMemory();Address start=address(p,item.address);
        Address end=address(p,item.last());
        if(covers(m,start,end)){
            notes.add("ALREADY MAPPED: "+item.name+" "+item.location());
            return false;
        }
        if(anyOverlap(m,start,end)){
            notes.add("SKIP PARTIAL OVERLAP: "+item.name+" "+item.location());
            return false;
        }
        MemoryBlock b=m.createUninitializedBlock(item.name,start,item.length,false);
        b.setRead(true);b.setWrite(true);b.setExecute(false);
        notes.add("NEW UNINITIALIZED BLOCK: "+item.name+" "+item.location());
        return true;
    }
    private static boolean defineRegister(Program p,HardwareApplyPlan.Item item,
                                          List<String> notes)throws Exception{
        Memory m=p.getMemory();Address start=address(p,item.address);
        Address end=address(p,item.last());
        if(!covers(m,start,end)){
            notes.add("SKIP UNMAPPED (select a memory block first): "+item.name);
            return false;
        }
        Listing listing=p.getListing();
        if(!listing.isUndefined(start,end)){
            notes.add("SKIP CODE/DEFINED DATA: "+item.name);
            return false;
        }
        Symbol prior=p.getSymbolTable().getPrimarySymbol(start);
        if(prior!=null && prior.getSource()!=SourceType.DEFAULT &&
                !item.name.equals(prior.getName())){
            notes.add("SKIP EXISTING USER LABEL: "+item.name+" -> "+prior.getName());
            return false;
        }
        DataType dt=item.length==2?WordDataType.dataType:DWordDataType.dataType;
        listing.createData(start,dt);
        if(prior==null || !item.name.equals(prior.getName())){
            // Stable unique name per 24-bit address. Do not rename prior symbol.
            String proposed=item.name+"_"+Long.toHexString(item.address).toUpperCase();
            p.getSymbolTable().createLabel(start,proposed,SourceType.USER_DEFINED);
        }
        notes.add("DEFINED REGISTER: "+item.name+" at "+start);
        return true;
    }
    private static boolean defineVbr(Program p,HardwareApplyPlan.Item item,
                                     List<String> notes)throws Exception{
        Memory m=p.getMemory();Address start=address(p,item.address);
        Address end=address(p,item.last());
        if(!covers(m,start,end)){
            notes.add("SKIP UNMAPPED VBR: "+item.location()+
                " (no new vector memory created implicitly)");
            return false;
        }
        if(!p.getListing().isUndefined(start,end)){
            notes.add("SKIP VBR: defined data or code exists in "+item.location()+
                ". Nothing is cleared or overwritten.");
            return false;
        }
        StructureDataType vectors=new StructureDataType(
            new CategoryPath("/GhidrAssist/Hardware"),
            "CPU32_VBR_256_VECTORS",0);
        for(int i=0;i<256;i++)
            vectors.add(DWordDataType.dataType,4,
                String.format("vector_%03d",i),
                "Vector table entry; meaning and runtime VBR unverified");
        DataType resolved=p.getDataTypeManager().addDataType(vectors,
            DataTypeConflictHandler.KEEP_HANDLER);
        p.getListing().createData(start,resolved);
        notes.add("CREATED 256-DWORD VBR STRUCTURE at "+start+
            " (no bytes changed; pointer targets not asserted)");
        return true;
    }
    /**
     * All rows are unchecked by default in UI. Transaction succeeds only
     * after explicit confirmation; failures rollback everything. Skipped
     * conflicts never clear or resize existing blocks/data.
     */
    public static Outcome apply(Program program,List<HardwareApplyPlan.Item> approved)
            throws Exception {
        if(program==null||approved==null||approved.isEmpty())
            throw new IllegalArgumentException("Nothing approved");
        int txn=program.startTransaction("GhidrAssist: Apply approved hardware definitions");
        boolean committed=false;int changed=0,skipped=0;
        List<String> notes=new ArrayList<>();
        try {
            // Regions first so their separately approved registers can be typed.
            for(HardwareApplyPlan.Kind kind:HardwareApplyPlan.Kind.values()){
                for(HardwareApplyPlan.Item item:approved){
                    if(item.kind!=kind)continue;
                    boolean did= switch(kind){
                        case MEMORY -> createBlock(program,item,notes);
                        case REGISTER -> defineRegister(program,item,notes);
                        case VBR_STRUCTURE -> defineVbr(program,item,notes);
                    };
                    if(did)changed++;else skipped++;
                }
            }
            committed=true;
            return new Outcome(changed,skipped,notes);
        } finally {
            program.endTransaction(txn,committed);
        }
    }
}
