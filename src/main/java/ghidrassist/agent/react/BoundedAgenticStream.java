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
        int available=capacity-value.length();
        int add=Math.max(0,Math.min(available,chunk.length()));
        if(add>0 && add<chunk.length() &&
                Character.isHighSurrogate(chunk.charAt(add-1)) &&
                Character.isLowSurrogate(chunk.charAt(add)))
            add--;
        if(add>0)value.append(chunk,0,add);
        if(add!=chunk.length())truncated=true;
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
