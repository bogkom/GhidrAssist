package ghidrassist.agent.react;

/**
 * GA-15: strictly bounded accumulation of untrusted streaming model text.
 * Records loss separately from the retained prefix: no omitted response
 * may be considered complete source evidence.
 *
 * Complete UTF-16 code points only: a high surrogate split across provider
 * callbacks is held privately until paired, rather than exposed to UI/RAG.
 */
public final class BoundedAgenticStream {
    public static final int MAX_ITERATION_CHARS=128*1024;
    public static final int MAX_DISPLAY_CHARS=32*1024;
    public static final int MAX_REFLECTION_CHARS=16*1024;

    private final StringBuilder value=new StringBuilder();
    private final int capacity;
    private boolean truncated;
    private char pendingHigh;

    public BoundedAgenticStream(int capacity) {
        if(capacity<1 || capacity>MAX_ITERATION_CHARS)
            throw new IllegalArgumentException("Invalid bounded stream capacity");
        this.capacity=capacity;
    }

    public synchronized void reset() {
        value.setLength(0);
        truncated=false;
        pendingHigh=0;
    }

    /**
     * True if input was irretrievably lost in this or any prior callback.
     * An unfinished high surrogate is NOT emitted; completeSource() must be
     * checked at provider completion even if append() has not flagged loss.
     * No intermediate copy is made of large or hostile callback text.
     */
    public synchronized boolean append(String chunk) {
        if(chunk==null || chunk.isEmpty())return truncated;
        int offset=0;
        if(pendingHigh!=0) {
            if(Character.isLowSurrogate(chunk.charAt(0)) &&
                    capacity-value.length()>=2) {
                value.append(pendingHigh).append(chunk.charAt(0));
                offset=1;
            } else {
                // A subsequent non-low callback or exhaustion means the
                // previous high surrogate was never valid evidence.
                truncated=true;
                if(Character.isLowSurrogate(chunk.charAt(0)))offset=1;
            }
            pendingHigh=0;
        }
        while(offset<chunk.length()) {
            if(value.length()>=capacity) {
                truncated=true;
                break;
            }
            char ch=chunk.charAt(offset);
            if(Character.isLowSurrogate(ch)) {
                truncated=true;
                offset++;
                continue;
            }
            if(Character.isHighSurrogate(ch)) {
                if(offset+1==chunk.length()) {
                    if(capacity-value.length()>=2)pendingHigh=ch;
                    else truncated=true;
                    break;
                }
                char next=chunk.charAt(offset+1);
                if(!Character.isLowSurrogate(next)) {
                    truncated=true;
                    offset++;
                    continue;
                }
                if(capacity-value.length()<2) {
                    truncated=true;
                    break;
                }
                value.append(ch).append(next);
                offset+=2;
                continue;
            }
            value.append(ch);
            offset++;
        }
        return truncated;
    }

    public synchronized boolean truncated() {return truncated;}
    /** No omitted units AND no dangling unmatched provider callback. */
    public synchronized boolean completeSource() {
        return !truncated && pendingHigh==0;
    }
    /** Never exposes an unmatched high surrogate as source evidence. */
    public synchronized String text() {return value.toString();}
    public synchronized int length() {return value.length();}

    /**
     * Constrain a complete provider response without retaining malformed
     * UTF-16, including unpaired surrogates anywhere in a short response.
     * The caller MUST also query fullResponseComplete() before asserting
     * that the response is complete source evidence.
     */
    public static String bounded(String response,int limit) {
        if(limit<1 || limit>MAX_ITERATION_CHARS)
            throw new IllegalArgumentException("Invalid full response limit");
        if(response==null)return null;
        var stream=new BoundedAgenticStream(limit);
        stream.append(response);
        return stream.text();
    }

    /** Distinguish a sanitized/shortened prefix from complete provider text. */
    public static boolean fullResponseComplete(String response,int limit) {
        if(limit<1 || limit>MAX_ITERATION_CHARS)
            throw new IllegalArgumentException("Invalid full response limit");
        if(response==null)return true;
        var stream=new BoundedAgenticStream(limit);
        stream.append(response);
        return stream.completeSource();
    }
}
