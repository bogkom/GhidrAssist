package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Proposal-only symbol naming. A CPU architecture or shared register-address
 * map never licenses a device-specific rename. No API for applying labels.
 */
public final class HardwareNamingReview {
    private HardwareNamingReview(){}

    public enum Status {
        FAMILY_UNCERTAIN, ALREADY_NAMED, NAME_COLLISION,
        EVIDENCE_TOO_WEAK, REVIEW_REQUIRED
    }
    public static final class Entry {
        public final long address;
        public final String existing, proposed, profile, register;
        public final int evidenceCount;
        public final Status status;
        Entry(long address,String existing,String proposed,String profile,String register,
                int evidenceCount,Status status){
            this.address=address;
            this.existing=existing;
            this.proposed=proposed;
            this.profile=profile;
            this.register=register;
            this.evidenceCount=evidenceCount;
            this.status=status;
        }
        public String csv(){
            return cell(ChipSelectModel.hex(address,6))+","+
                cell(existing)+","+cell(proposed)+","+cell(profile)+","+
                cell(register)+","+evidenceCount+","+cell(status.name())+"\n";
        }
    }
    public static List<Entry> propose(boolean selectedConcreteProfile,
            String profile,Map<Long,String> registerNames,Map<Long,String> existing,
            Map<Long,Integer> counts,Collection<String> allDefinedSymbolNames) {
        if(registerNames==null||existing==null||counts==null||allDefinedSymbolNames==null)
            throw new IllegalArgumentException("Null naming input");
        Set<String> reserved=new HashSet<>();
        for(String value:allDefinedSymbolNames)
            if(value!=null)reserved.add(value.toUpperCase(Locale.ROOT));
        List<Entry> rows=new ArrayList<>();
        for(Map.Entry<Long,String> r:registerNames.entrySet()){
            long address=r.getKey();
            String name=r.getValue()==null?"UNKNOWN":r.getValue();
            String previous=existing.getOrDefault(address,"");
            int references=counts.getOrDefault(address,0);
            String candidate=selectedConcreteProfile ?
                ("HW_"+profile+"_"+name+"_"+(address>=0x800000?"MM1":"MM0"))
                .replaceAll("[^a-zA-Z0-9_]","_") : "";
            boolean knownName=!previous.isBlank() &&
                !previous.startsWith("DAT_") &&
                !previous.startsWith("LAB_") &&
                !previous.startsWith("UNK_");
            Status reason;
            if(!selectedConcreteProfile)reason=Status.FAMILY_UNCERTAIN;
            else if(knownName)reason=Status.ALREADY_NAMED;
            else if(references<2)reason=Status.EVIDENCE_TOO_WEAK;
            else if(reserved.contains(candidate.toUpperCase(Locale.ROOT)))
                reason=Status.NAME_COLLISION;
            else reason=Status.REVIEW_REQUIRED;
            rows.add(new Entry(address,previous,
                reason==Status.REVIEW_REQUIRED?candidate:"",
                profile,name,references,reason));
        }
        return List.copyOf(rows);
    }
    private static String cell(String value){
        return "\""+(value==null?"":value).replace("\"","\"\"")
            .replace("\r"," ").replace("\n"," ")+"\"";
    }
    public static String toCsv(List<Entry> entries){
        StringBuilder b=new StringBuilder(
            "address,existing_name,proposed_name,profile,register,evidence_count,status\n");
        for(Entry row:entries)b.append(row.csv());
        return b.toString();
    }
}
