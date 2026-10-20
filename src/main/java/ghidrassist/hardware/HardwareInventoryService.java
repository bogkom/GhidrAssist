package ghidrassist.hardware;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Read-only, source-provenanced Ghidra evidence for hypothetical internal MCU
 * registers. The same MC68332 candidate address may be shared by other CPU32
 * devices. All generated windows are configuration *sketches* grouped by Ghidra
 * function; they do not imply that those functions execute or execute in order.
 */
public final class HardwareInventoryService {
    public static final class Site {
        public final Address pc;
        public final long registerAddress;
        public final String register;
        public final String function;
        public final String asm;
        public final boolean write;
        public final Integer literal;
        private Site(Address pc,long address,String register,String function,
                String asm,boolean write,Integer literal){
            this.pc=pc;
            this.registerAddress=address;
            this.register=register;
            this.function=function;
            this.asm=asm;
            this.write=write;
            this.literal=literal;
        }
    }
    public static final class Report {
        public final String program,language,selection;
        public final int uniqueSites,functions;
        public final List<Site> sites;
        public final String markdown;
        private Report(String program,String language,String selection,List<Site> sites,
                String markdown,int functions){
            this.program=program;
            this.language=language;
            this.selection=selection;
            this.uniqueSites=sites.size();
            this.sites=List.copyOf(sites);
            this.markdown=markdown;
            this.functions=functions;
        }
    }

    private static String hex(long v,int n) {
        return ChipSelectModel.hex(v,n);
    }
    private static String mnemonic(Instruction insn){
        String name=insn.getMnemonicString().toUpperCase(Locale.ROOT);
        int dot=name.indexOf('.');
        return dot<0?name:name.substring(0,dot);
    }
    private static long referenceDestination(Instruction insn,int op){
        Object[] obj=insn.getOpObjects(op);
        if(obj==null)return -1;
        for(Object o:obj)if(o instanceof Address a)return a.getOffset();
        return -1;
    }
    private static Integer literalWord(Instruction i,long target) {
        if(i.getNumOperands()<1)return null;
        int last=i.getNumOperands()-1;
        String dest=i.getDefaultOperandRepresentation(last);
        if(dest==null || dest.contains("#") || referenceDestination(i,last)!=target)
            return null;
        if(!i.getMnemonicString().toUpperCase(Locale.ROOT).endsWith(".W"))
            return null;
        if(i.getNumOperands()==1 && mnemonic(i).equals("CLR"))
            return 0;
        if(i.getNumOperands()==2 && mnemonic(i).equals("MOVE")){
            String source=i.getDefaultOperandRepresentation(0);
            Scalar s=i.getScalar(0);
            if(source!=null && source.trim().startsWith("#") && s!=null)
                return (int)(s.getUnsignedValue()&0xffff);
        }
        return null;
    }
    private static boolean knownWrite(Instruction i,long target){
        int last=i.getNumOperands()-1;
        if(last<0||referenceDestination(i,last)!=target)return false;
        return switch(mnemonic(i)){
            case "MOVE","MOVEA","CLR","ORI","ANDI","EORI",
                 "BSET","BCLR","ADD","ADDI","SUB","SUBI" -> true;
            default -> false;
        };
    }
    public Report scan(Program program,boolean concreteDevice,TaskMonitor monitor)
            throws CancelledException {
        if(program==null)throw new IllegalArgumentException("A loaded Ghidra program is required");
        if(monitor==null)monitor=TaskMonitor.DUMMY;
        HardwareProfiles.Profile profile=HardwareProfiles.mc68332();
        Map<Long,HardwareProfiles.Register> byAddress=new LinkedHashMap<>();
        for(HardwareProfiles.Register r:profile.registers)
            for(int mm=0;mm<2;mm++)
                byAddress.put(profile.absoluteAddress(r,mm),r);
        Map<String,Site> found=new LinkedHashMap<>();
        for(Map.Entry<Long,HardwareProfiles.Register> record:byAddress.entrySet()){
            monitor.checkCancelled();
            Address dest=program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(record.getKey());
            ReferenceIterator refs=program.getReferenceManager().getReferencesTo(dest);
            while(refs.hasNext()){
                monitor.checkCancelled();
                Reference ref=refs.next();
                Instruction i=program.getListing().getInstructionContaining(ref.getFromAddress());
                if(i==null)continue;
                Function f=program.getFunctionManager().getFunctionContaining(i.getAddress());
                String fn=f==null?"<unrecognized>":f.getName()+" @ "+f.getEntryPoint();
                boolean write=knownWrite(i,record.getKey());
                String key=i.getAddress()+"/"+record.getKey();
                Site current=new Site(i.getAddress(),record.getKey(),record.getValue().name,
                    fn,i.toString(),write,write?literalWord(i,record.getKey()):null);
                found.putIfAbsent(key,current);
            }
        }
        // For raw binary programs whose references have not been initialized:
        // supplement only direct absolute destination forms, not generic
        // constants that might accidentally equal internal-module addresses.
        InstructionIterator iterator=program.getListing().getInstructions(true);
        int scanned=0;
        while(iterator.hasNext()){
            monitor.checkCancelled();
            Instruction i=iterator.next();scanned++;
            int last=i.getNumOperands()-1;
            if(last<0)continue;
            long addr=referenceDestination(i,last);
            HardwareProfiles.Register reg=byAddress.get(addr);
            if(reg==null || !knownWrite(i,addr))continue;
            String key=i.getAddress()+"/"+addr;
            if(found.containsKey(key))continue;
            Function f=program.getFunctionManager().getFunctionContaining(i.getAddress());
            String fn=f==null?"<unrecognized>":f.getName()+" @ "+f.getEntryPoint();
            found.put(key,new Site(i.getAddress(),addr,reg.name,fn,i.toString(),true,
                literalWord(i,addr)));
        }
        List<Site> sites=new ArrayList<>(found.values());
        sites.sort(Comparator.comparing((Site s)->s.function)
            .thenComparing(s->s.pc).thenComparingLong(s->s.registerAddress));
        Map<String,List<Site>> grouped=new LinkedHashMap<>();
        for(Site site:sites)grouped.computeIfAbsent(site.function,k->new ArrayList<>()).add(site);
        String choice=concreteDevice?"MC68332 (MANUALLY ASSUMED)":"CPU32 (MC68332-ADDRESS RECONNAISSANCE)";
        StringBuilder md=new StringBuilder();
        md.append("# Hardware Evidence — read-only\n\n")
          .append("- Program: \`").append(program.getName()).append("\`\n")
          .append("- Ghidra language: \`").append(program.getLanguageID()).append("\`\n")
          .append("- Selection: **").append(choice).append("**\n")
          .append("- Scanned Listing instructions: ").append(scanned).append("\n")
          .append("- Unique instruction/register reference sites: ").append(sites.size()).append("\n")
          .append("- Firmware origin: currently loaded Ghidra project, NOT a device readback\n")
          .append("- MCU identity, active MM map, reached branches, connected chips and memory wiring: **NOT VERIFIED**\n")
          .append("- Register address provenance: [MC68332 User's Manual](https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf)\n\n");
        md.append("## Function-local evidence (no runtime ordering guarantee)\n\n");
        ChipSelectModel.Decoder decoder=new ChipSelectModel.Decoder(
            "MC68332","MC68332 manual; provisional code-site constants");
        for(Map.Entry<String,List<Site>> group:grouped.entrySet()){
            monitor.checkCancelled();
            md.append("### ").append(group.getKey()).append("\n\n");
            // Different MM windows never form one combined state.
            for(int mm=0;mm<=1;mm++){
                Map<String,Integer> values=new LinkedHashMap<>();
                boolean any=false;
                for(Site site:group.getValue()){
                    if((site.registerAddress<0x800000L?0:1)!=mm)continue;
                    any=true;
                    md.append("- \`").append(site.pc).append("\` ")
                      .append(site.register).append(" \`")
                      .append(hex(site.registerAddress,6)).append("\` — ")
                      .append(site.write?"WRITE":"READ/REFERENCE")
                      .append("; ").append(site.literal==null?"value UNKNOWN":hex(site.literal,4))
                      .append("; \`").append(site.asm).append("\`\n");
                    if(site.write){
                        if(site.literal==null)values.remove(site.register);
                        else values.put(site.register,site.literal);
                    }
                }
                if(!any)continue;
                md.append("\n**MM=").append(mm).append(" conditional linear-code snapshot**\n\n");
                if(!values.isEmpty()){
                    List<ChipSelectModel.Window> windows=new ArrayList<>();
                    for(int cs=-1;cs<=10;cs++){
                        String label=cs<0?"BT":Integer.toString(cs);
                        String pin=cs<=5?"CSPAR0":"CSPAR1";
                        ChipSelectModel.Window window=decoder.window(cs,
                            values.get("CSBAR"+label),values.get("CSOR"+label),values.get(pin));
                        if(window==null)continue;
                        windows.add(window);
                        md.append("- ").append(window.toSummary()).append("\n");
                    }
                    List<String> overlaps=ChipSelectModel.overlaps(windows);
                    for(String overlap:overlaps)md.append("- shared address hypothesis: ").append(overlap).append("\n");
                }
                md.append("\n");
            }
        }
        md.append("## Important limitations\n\n")
          .append("1. Site order is address order, **not a proven execution trace**. Last-write-wins cannot be assumed across branches/calls.\n")
          .append("2. No constant propagation across register pointers, indirect writes, loops or interprocedural paths. Unknown writes invalidate values.\n")
          .append("3. CSBAR gives only a *potential* window. CSOR, CSPAR, MM, CPU function codes, exception/boot state, bus wiring and external device presence remain separate requirements.\n")
          .append("4. VBR is a CPU control register; read separate VBR analysis. A register address match is not proof of a particular physical MCU.\n")
          .append("5. This report is usable as RAG context with uncertainty preserved; do not automatically rename functions, set memory blocks or program any u-Link NT address from it.\n");
        return new Report(program.getName(),program.getLanguageID().toString(),choice,sites,
            md.toString(),grouped.size());
    }
}
