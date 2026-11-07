package ghidrassist.agent.react;

/**
 * GA-15: strictly bounded accumulation of untrusted streaming model text.
 * Records loss separately from the retained prefix: no omitted response
 * may be considered complete source evidence.
 */
public final class BoundedAgenticStream {
    public static final int MAX_ITERATION_CHARS=128*1024;
    public static final int MAX_DISPLAY_CHARS=32*1024;
    public static final int MAX_REFLECTION_CHARS=16*1024;

    private final StringBuilder value=new StringBuilder();
    private final int capacity;
    private boolean truncated;

    public BoundedAgenticStream(int capacity) {
        if(capacity<1 || capacity>MAX_ITERATION_CHARS)
            throw new IllegalArgumentException("Invalid bounded stream capacity");
        this.capacity=capacity;
    }

    public synchronized void reset() {
        value.setLength(0);
        truncated=false;
    }

    /**
     * True if some input was dropped in this or any earlier append.
     * The entire untrusted chunk is never copied into a temporary buffer.
     */
    public synchronized boolean append(String chunk) {
        if(chunk==null || chunk.isEmpty())return truncated;
        // A provider may split a UTF-16 surrogate pair across two callbacks.
        // Never retain an orphan low surrogate or a high surrogate at the
        // hard capacity boundary. Overflow is sticky even across callbacks.
        int offset=0;
        if(Character.isLowSurrogate(chunk.charAt(0)) &&
                (value.length()==0 ||
                 !Character.isHighSurrogate(value.charAt(value.length()-1)))) {
            offset=1;
            truncated=true;
        }
        int available=capacity-value.length();
        int add=Math.max(0,Math.min(available,chunk.length()-offset));
        if(add>0 && offset+add<chunk.length() &&
                Character.isHighSurrogate(chunk.charAt(offset+add-1)) &&
                Character.isLowSurrogate(chunk.charAt(offset+add)))
            add--;
        // If the buffer would finish with a dangling high surrogate,
        // reserve the last code unit conservatively and mark source loss.
        if(add>0 && add==available &&
                Character.isHighSurrogate(chunk.charAt(offset+add-1)))
            add--;
        if(add>0)value.append(chunk,offset,offset+add);
        if(add!=chunk.length()-offset)truncated=true;
        return truncated;
    }

    public synchronized boolean truncated() {return truncated;}
    public synchronized String text() {return value.toString();}
    public synchronized int length() {return value.length();}

    /** Constrain a single full provider callback without trusting its size. */
    public static String bounded(String response,int limit) {
        if(response==null || response.length()<=limit)return response;
        if(limit<1 || limit>MAX_ITERATION_CHARS)
            throw new IllegalArgumentException("Invalid full response limit");
        int stop=limit;
        if(Character.isHighSurrogate(response.charAt(stop-1)) &&
                Character.isLowSurrogate(response.charAt(stop)))stop--;
        return response.substring(0,stop);
    }
}
