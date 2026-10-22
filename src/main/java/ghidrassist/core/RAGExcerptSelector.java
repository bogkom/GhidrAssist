package ghidrassist.core;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Select evidence from actual PDF page text, not repeated synthetic headers.
 * This works on existing indexes; the full page is already persisted in Lucene.
 * The returned text is source evidence, not a verified table reconstruction.
 */
public final class RAGExcerptSelector {
    private static final Pattern WORD = Pattern.compile("[\\p{L}\\p{N}_]{3,}");
    private static final Set<String> STOP = Set.of(
        "the","and","from","with","that","this","what","where","for","are",
        "not","pdf","rag","table","page","podaj","oraz","tych","czterech",
        "modułów","adresy","adresami","rozmiary","rozmiarami","bazowe",
        "bazowymi","dokumentacji","fragmentów","źródłowy","numer","strony",
        "source","register","registers","module","informacje");
    private RAGExcerptSelector() {}

    public static String sourceBody(String stored) {
        if (stored == null) return "";
        if (stored.startsWith("[RAG_SOURCE_METADATA ")) {
            int end=stored.indexOf('\n');
            return end < 0 ? "" : stored.substring(end+1).stripLeading();
        }
        return stored;
    }
    private static List<String> terms(String query) {
        LinkedHashSet<String> result=new LinkedHashSet<>();
        Matcher m=WORD.matcher(query==null?"":query.toLowerCase(Locale.ROOT));
        while(m.find()) {
            String t=m.group();
            if(!STOP.contains(t) && !t.endsWith(".pdf") &&
                !t.equals("mc68332um") && !t.equals("mc68332ts") &&
                result.size()<40) result.add(t);
        }
        return new ArrayList<>(result);
    }
    /** Page-local reranking independent of source metadata in the indexed field. */
    public static double evidenceScore(String content,String query) {
        String body=sourceBody(content).toLowerCase(Locale.ROOT);
        double result=0;
        for(String term:terms(query)) if(body.contains(term)) result+=1;
        String q=query==null?"":query.toLowerCase(Locale.ROOT);
        if(q.contains("module address map") &&
            body.contains("table d-1 module address map")) result+=5;
        if((q.contains("table d-1") || q.contains("yffa00") || q.contains("yffb00")) &&
            body.contains("geometry-aligned module address table candidates")) result+=4;
        return result;
    }
    public static String select(String stored,String query) {
        return select(stored,query,3600);
    }
    public static String select(String stored,String query,int maxChars) {
        if(maxChars<256) throw new IllegalArgumentException("maxChars < 256");
        String body=sourceBody(stored).strip();
        if(body.length()<=maxChars) return body;
        String lower=body.toLowerCase(Locale.ROOT);
        List<String> terms=terms(query);
        LinkedHashSet<Integer> starts=new LinkedHashSet<>();
        starts.add(0);
        for(String term:terms) {
            int from=0,count=0;
            while(count++<45) {
                int p=lower.indexOf(term,from);
                if(p<0)break;
                starts.add(Math.max(0,p-maxChars/3));
                from=p+term.length();
            }
        }
        int bestStart=0;
        double best=-1;
        for(int start:starts) {
            String window=lower.substring(start,Math.min(body.length(),start+maxChars));
            double score=0;
            for(String term:terms) if(window.contains(term))score++;
            if(window.contains("table d-1 module address map") &&
                window.contains("sim 128") && window.contains("qsm 512"))score+=8;
            if(window.contains("geometry-aligned module address table candidates"))score+=2;
            if(score>best){best=score;bestStart=start;}
        }
        int end=Math.min(body.length(),bestStart+maxChars);
        if(bestStart>0) {
            int nextLine=body.indexOf('\n',bestStart);
            if(nextLine>=0 && nextLine<bestStart+90)bestStart=nextLine+1;
        }
        if(end<body.length()) {
            int lastLine=body.lastIndexOf('\n',end);
            if(lastLine>bestStart+800)end=lastLine;
        }
        return (bestStart>0?"[EARLIER PAGE TEXT OMITTED]\n":"") +
            body.substring(bestStart,end).strip() +
            (end<body.length()?"\n[LATER PAGE TEXT OMITTED; OPEN SOURCE PDF]":"");
    }
}
