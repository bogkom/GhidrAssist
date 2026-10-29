package ghidrassist.hardware;

import java.util.*;

/**
 * Read-only role hints for A-registers at CFG-resolved indirect MMIO sites.
 * An A-register at a code site is NOT a persistent Ghidra local variable,
 * and none of these proposals may be applied automatically.
 */
public final class HardwarePointerRoleReview {
    private HardwarePointerRoleReview() {}
    public enum Status { FAMILY_UNCERTAIN, PATH_UNCERTAIN, SCOPE_CONFLICT, WEAK_EVIDENCE, REVIEW_ONLY }
    public record Site(long function, String functionName, long pc, String pointer,
                       String module, int mm, String target, boolean uncertain) {}
    public record Proposal(long function,String functionName,String pointer,String module,
                           int mm,int sites,int registers,Status status,String hint) {
        public String details(){
            return String.format(Locale.ROOT,
                "function 0x%08X; %s -> %s/MM%d; %d static PCs, %d register targets; %s",
                function,pointer,module,mm,sites,registers,status);
        }
        public String csv(){
            return cell(String.format(Locale.ROOT,"0x%08X",function))+","+
                cell(pointer+" in "+functionName)+","+cell(hint)+","+
                cell("MC68332 MANUAL HYPOTHESIS")+","+
                cell("POINTER_ROLE:"+module+":MM"+mm)+","+sites+","+
                cell(status+"; NEVER_AUTO_APPLY")+"\n";
        }
    }
    private static String cell(String v) {
        return "\""+v.replace("\"","\"\"").replace("\r"," ").replace("\n"," ")+"\"";
    }
    private static class Group {
        final Site first;
        final Set<Long> pcs=new LinkedHashSet<>();
        final Set<String> targets=new LinkedHashSet<>();
        boolean uncertain;
        Group(Site site){first=site;}
        void add(Site s){pcs.add(s.pc());targets.add(s.target());uncertain|=s.uncertain();}
    }
    public static List<Proposal> propose(boolean concrete,Collection<Site> input,
                                         boolean truncated) {
        if(input==null)throw new IllegalArgumentException("Null pointer evidence");
        Map<String,Group> grouped=new TreeMap<>();
        // A0..A7 are physical registers, NOT stable local variables.
        // Reusing one address register for different module/MM scopes in
        // a function invalidates an otherwise attractive single-role hint.
        Map<String,Set<String>> pointerScopes=new HashMap<>();
        for(Site s:input){
            if(s==null || s.function()<0 || s.pc()<0 ||
                    s.functionName()==null || s.target()==null ||
                    s.module()==null || !s.module().matches("[A-Z0-9_]{2,24}") ||
                    s.pointer()==null || !s.pointer().matches("A[0-7]") ||
                    (s.mm()!=0 && s.mm()!=1))continue;
            String key=String.format(Locale.ROOT,"%016X/%s/%s/%d",
                s.function(),s.pointer(),s.module(),s.mm());
            grouped.computeIfAbsent(key,k->new Group(s)).add(s);
            String pointerKey=String.format(Locale.ROOT,"%016X/%s",
                s.function(),s.pointer());
            pointerScopes.computeIfAbsent(pointerKey,k->new HashSet<>())
                .add(s.module()+"/MM"+s.mm());
        }
        List<Proposal> result=new ArrayList<>();
        for(Group g:grouped.values()) {
            if(g.pcs.size()<2)continue;
            Site s=g.first;
            String pointerKey=String.format(Locale.ROOT,"%016X/%s",
                s.function(),s.pointer());
            boolean conflictingScopes=pointerScopes.get(pointerKey).size()>1;
            Status status=!concrete?Status.FAMILY_UNCERTAIN:
                truncated||g.uncertain?Status.PATH_UNCERTAIN:
                conflictingScopes?Status.SCOPE_CONFLICT:
                g.targets.size()<2?Status.WEAK_EVIDENCE:Status.REVIEW_ONLY;
            String hint=status==Status.REVIEW_ONLY ?
                "p_hw_"+s.module().toLowerCase(Locale.ROOT)+"_mm"+s.mm()+"_candidate":"";
            result.add(new Proposal(s.function(),s.functionName(),s.pointer(),
                s.module(),s.mm(),g.pcs.size(),g.targets.size(),status,hint));
        }
        return List.copyOf(result);
    }
    public static String csvRows(List<Proposal> rows) {
        StringBuilder b=new StringBuilder();
        for(Proposal p:rows)b.append(p.csv());
        return b.toString();
    }
    public static String report(List<Proposal> rows) {
        StringBuilder b=new StringBuilder("## Function-scoped A-register role candidates\n\n")
            .append("Read-only, static CFG/P-code site evidence; NOT proof of ")
            .append("runtime execution, pointer lifetime, Ghidra decompiler ")
            .append("HighVariable identity or hardware address map. ")
            .append("No pointer/variable rename is implemented. Reuse of ")
            .append("the same A-register across module/MM scopes in a function ")
            .append("is SCOPE_CONFLICT, never a stable pointer-role hint.\n\n")
            .append("- Candidate groups: ").append(rows.size()).append(".\n");
        for(int i=0;i<Math.min(50,rows.size());i++) {
            Proposal p=rows.get(i);
            b.append("- ").append(p.details());
            if(!p.hint().isBlank())b.append("; role hint ").append(p.hint());
            b.append("\n");
        }
        if(rows.size()>50)b.append("- Remaining groups omitted from display.\n");
        return b.append("\n").toString();
    }
}
