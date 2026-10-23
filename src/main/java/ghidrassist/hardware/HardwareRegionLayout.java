package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Pure-Java interval planner for safe migration of previously approved
 * disjoint MMIO blocks. Does not mutate Ghidra; refuses overlaps and spans
 * outside the selected module boundary.
 */
public final class HardwareRegionLayout {
    private HardwareRegionLayout(){}
    public static final class Range {
        public final long first,last;
        public Range(long first,long last){
            if(first<0||last<first||last>0xffffffL)
                throw new IllegalArgumentException("Invalid 24-bit range");
            this.first=first;this.last=last;
        }
        public long length(){return last-first+1;}
    }
    /**
     * Compute unmapped gaps when unrelated existing blocks are allowed to extend
     * beyond the proposed CS range. Existing bytes are never moved or overwritten.
     */
    public static List<Range> missingClipped(long first,long last,List<Range> existing){
        if(first<0||last<first||last>0xffffffL)
            throw new IllegalArgumentException("Invalid CS range");
        List<Range> sorted=new ArrayList<>(existing);
        sorted.sort(Comparator.comparingLong(r->r.first));
        List<Range> gaps=new ArrayList<>();
        long cursor=first;
        for(Range segment:sorted){
            if(segment.last<first||segment.first>last)continue;
            long begin=Math.max(first,segment.first);
            long end=Math.min(last,segment.last);
            if(begin>cursor)gaps.add(new Range(cursor,begin-1));
            cursor=Math.max(cursor,end+1);
        }
        if(cursor<=last)gaps.add(new Range(cursor,last));
        return List.copyOf(gaps);
    }
    public static List<Range> missing(long first,long last,List<Range> existing){
        if(first<0||last<first||last>0xffffffL)
            throw new IllegalArgumentException("Invalid module address range");
        List<Range> sorted=new ArrayList<>(existing);
        sorted.sort(Comparator.comparingLong(r->r.first));
        List<Range> gaps=new ArrayList<>();
        long next=first;
        for(Range segment:sorted){
            if(segment.first<next||segment.last>last)
                throw new IllegalArgumentException("Overlap or range outside module");
            if(segment.first>next)gaps.add(new Range(next,segment.first-1));
            next=segment.last+1;
        }
        if(next<=last)gaps.add(new Range(next,last));
        return List.copyOf(gaps);
    }
}
