package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Read-only gate between register evidence and optional Review/Apply
 * memory-window *proposals*. No assertion of hardware CS activation.
 */
public final class HardwareCsbarReviewGate {
    private HardwareCsbarReviewGate(){}
    private static final Pattern CSBAR=Pattern.compile("CSBAR(10|[0-9])");
    private static final long CSBAR_BT_MM1=0xfffa48L;
    private static final long CSBAR0_MM1=0xfffa4cL;

    public record Source(String function,String register,long address,
                         boolean candidateWrite,Integer literalWord) {
        public Source {
            if(function==null || register==null || register.isBlank() ||
                    address<0 || literalWord!=null &&
                    (literalWord<0 || literalWord>0xffff))
                throw new IllegalArgumentException("Invalid CSBAR source");
        }
    }
    public record Candidate(String register,int word,String origin,
                            int independentSiteCount) {}
    public record Result(List<Candidate> candidates,int excludedWrongWindow,
                         int conflictedRegisters,int unknownWriteRegisters) {
        public Result {candidates=List.copyOf(candidates);}
        public String explanation(){
            return "Review/Apply CSBAR candidates="+candidates.size()+
                "; rejected non-MM1/non-CSBAR references="+excludedWrongWindow+
                "; conflicting word values="+conflictedRegisters+
                "; missing full-word values="+unknownWriteRegisters+
                "; all candidates require manual review and do NOT establish "+
                "active MM map or external chip selection";
        }
    }
    private static Long expectedAddress(String name){
        if(name.equals("CSBARBT"))return CSBAR_BT_MM1;
        Matcher m=CSBAR.matcher(name);
        if(!m.matches())return null;
        int index=Integer.parseInt(m.group(1));
        return CSBAR0_MM1+4L*index;
    }
    private static final class Group {
        final String register;
        final Set<String> sources=new LinkedHashSet<>();
        Integer literal;
        boolean unknown,conflict;
        int writes;
        Group(String name){register=name;}
        void add(Source s){
            if(!s.candidateWrite())return;
            writes++;
            sources.add(s.function());
            if(s.literalWord()==null)unknown=true;
            else if(literal==null)literal=s.literalWord();
            else if(!literal.equals(s.literalWord()))conflict=true;
        }
        String origins(){
            StringBuilder result=new StringBuilder();
            int shown=0;
            for(String source:sources){
                if(shown++>=3)break;
                if(result.length()>0)result.append("; ");
                result.append(source.replace('\n',' ').replace('\r',' '));
            }
            if(sources.size()>3)result.append("; +")
                .append(sources.size()-3).append(" other functions");
            return result.toString();
        }
    }
    public static Result reviewCandidates(List<Source> observations) {
        if(observations==null)throw new IllegalArgumentException("Missing CSBAR observations");
        Map<String,Group> groups=new LinkedHashMap<>();
        int notMm1=0;
        for(Source s:observations){
            if(s==null)throw new IllegalArgumentException("Null CSBAR observation");
            Long expected=expectedAddress(s.register());
            if(expected==null || expected!=s.address()){
                notMm1++;continue;
            }
            groups.computeIfAbsent(s.register(),Group::new).add(s);
        }
        List<Candidate> accepted=new ArrayList<>();
        int conflicts=0,unknown=0;
        for(Group g:groups.values()){
            if(g.conflict){conflicts++;continue;}
            if(g.unknown){unknown++;continue;}
            if(g.literal!=null && g.writes>0)
                accepted.add(new Candidate(g.register,g.literal,g.origins(),g.writes));
        }
        accepted.sort(Comparator.comparing(Candidate::register));
        return new Result(accepted,notMm1,conflicts,unknown);
    }
}
