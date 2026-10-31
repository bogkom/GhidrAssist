package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Bounded, read-only source-evidence accumulator.
 * A sample never silently appears complete when a source site was dropped.
 * The dropped count cannot be used to claim absent hardware writes.
 */
public final class HardwareEvidenceBudget<T> {
    private final int max;
    private final List<T> collected;
    private long totalSeen;

    public HardwareEvidenceBudget(int max) {
        if(max<1 || max>1_000_000)
            throw new IllegalArgumentException("Invalid source-evidence budget");
        this.max=max;
        this.collected=new ArrayList<>(Math.min(max,1024));
    }
    public void offer(T site) {
        Objects.requireNonNull(site,"Missing source-evidence site");
        if(totalSeen==Long.MAX_VALUE)
            throw new IllegalStateException("Source count overflow");
        totalSeen++;
        if(collected.size()<max)collected.add(site);
    }
    public boolean truncated() { return totalSeen>collected.size(); }
    public long omitted() {return totalSeen-collected.size();}
    public long totalSeen() {return totalSeen;}
    public int retained() {return collected.size();}
    public List<T> snapshot() {return List.copyOf(collected);}
    /** Source completeness is a prerequisite for a confident review hint. */
    public boolean safeAsComplete(boolean parentCfgComplete) {
        return parentCfgComplete && !truncated();
    }
    public String provenance(){
        return "source sites seen="+totalSeen+
            ", retained="+collected.size()+", omitted="+omitted()+
            "; bounded candidate evidence; truncation does NOT prove no "+
            "additional writes, branches or aliases";
    }
}
