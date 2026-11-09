package ghidrassist.agent.react;

/** Java 21 deterministic GA-15 source-limiting regression, no external AI. */
public final class BoundedAgenticStreamSelfTest {
    private static void check(boolean truth,String message) {
        if(!truth)throw new AssertionError(message);
    }

    public static void main(String[] args) {
        var tiny=new BoundedAgenticStream(8);
        check(!tiny.append("abc"),"short prefix flagged");
        check(tiny.length()==3 && tiny.text().equals("abc"),"prefix");
        check(tiny.append("defghijkl"),"overflow was not flagged");
        check(tiny.length()==8 && tiny.text().equals("abcdefgh"),"cap exceeded");
        check(tiny.append("new ignored text") && tiny.length()==8,
            "unbounded append after overflow");
        tiny.reset();
        check(!tiny.truncated() && tiny.length()==0,"reset failed");
        check(!tiny.append("abcdefgh") && !tiny.truncated(),"exact cap");
        check(tiny.append("x"),"one extra unit must mark omitted source");

        String smile="a"+new String(Character.toChars(0x1f603));
        var unicode=new BoundedAgenticStream(2);
        check(unicode.append(smile),"split surrogate not marked");
        check("a".equals(unicode.text()),"split surrogate pair leaked");
        check("a".equals(BoundedAgenticStream.bounded(
            smile,2)),"full callback split surrogate pair");

        // Two separate streaming callbacks split a surrogate pair exactly
        // where the buffer would otherwise store an orphan high surrogate.
        var splitCap=new BoundedAgenticStream(2);
        check(splitCap.append(smile.substring(0,2)), "orphan high surrogate not dropped");
        check("a".equals(splitCap.text()), "unsafe surrogate retained at cap");
        check(splitCap.append(smile.substring(2)) && "a".equals(splitCap.text()),
            "orphan low surrogate leaked after full buffer");
        var splitSafe=new BoundedAgenticStream(4);
        check(!splitSafe.append(smile.substring(0,2)) &&
                !splitSafe.append(smile.substring(2)) &&
                splitSafe.text().equals(smile),
            "valid surrogate pair spanning callbacks lost before capacity");
        var orphanLow=new BoundedAgenticStream(3);
        check(orphanLow.append(smile.substring(2)) && orphanLow.length()==0,
            "unpaired low surrogate accepted from independent callback");

        char high=(char)0xD83D, low=(char)0xDE03;
        // A withheld high surrogate is never sent to the UI/RAG as
        // a dangling UTF-16 unit; a later callback can complete it.
        var pending=new BoundedAgenticStream(8);
        check(!pending.append("a"+high) && pending.text().equals("a") &&
                !pending.completeSource(),
            "Pending high surrogate must not become complete source evidence");
        check(!pending.append(String.valueOf(low)) &&
                pending.completeSource() && pending.text().equals(smile),
            "Valid split callback pair is reconstructed without source loss");
        var invalidNext=new BoundedAgenticStream(8);
        invalidNext.append("a"+high);
        check(invalidNext.append("X") &&
                invalidNext.text().equals("aX") &&
                !invalidNext.completeSource(),
            "Unpaired high followed by normal data drops malformed unit");
        var orphanMiddle=new BoundedAgenticStream(16);
        check(orphanMiddle.append("abc"+low+"def") &&
                orphanMiddle.text().equals("abcdef") &&
                !orphanMiddle.completeSource(),
            "Unpaired low surrogate in callback is not retained");
        var twoHigh=new BoundedAgenticStream(16);
        check(twoHigh.append("a"+high+high) &&
                twoHigh.text().equals("a") &&
                !twoHigh.completeSource(),
            "Adjacent high surrogates cannot masquerade as complete response");
        check(!BoundedAgenticStream.fullResponseComplete(
                "hello"+high,20) &&
                BoundedAgenticStream.bounded("hello"+high,20).equals("hello"),
            "Malformed trailing high in short full callback must be detected");
        check(!BoundedAgenticStream.fullResponseComplete(
                "a"+low+"b",20) &&
                BoundedAgenticStream.bounded("a"+low+"b",20).equals("ab"),
            "Malformed low surrogate stripped from short full response");
        check(BoundedAgenticStream.fullResponseComplete(smile,3) &&
                BoundedAgenticStream.bounded(smile,3).equals(smile) &&
                !BoundedAgenticStream.fullResponseComplete(smile,2),
            "Source completeness respects whole emoji across hard limit");
        var splitEnd=new BoundedAgenticStream(3);
        check(!splitEnd.append("a"+high) &&
                !splitEnd.completeSource() &&
                splitEnd.text().equals("a"),
            "Pending final high cannot be emitted despite available capacity");
        splitEnd.reset();
        check(splitEnd.completeSource() && splitEnd.text().isEmpty(),
            "Reset discards prior callback's pending high");
        for(int limit:new int[]{0,-1,BoundedAgenticStream.MAX_ITERATION_CHARS+1}){
            boolean rejected=false;
            try{BoundedAgenticStream.bounded("short",limit);}
            catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"Invalid limit rejected even for short full response");
            rejected=false;
            try{BoundedAgenticStream.fullResponseComplete("short",limit);}
            catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"Invalid completeness cap rejected before short bypass");
        }
        check(BoundedAgenticStream.bounded(null,4)==null &&
                BoundedAgenticStream.fullResponseComplete(null,4),
            "Missing full callback must not fabricate any source text");

        var cache=new FindingsCache(1);
        cache.addFinding("one complete observation","source","listing",9);
        var baseline=cache.page(0,100);
        check(baseline.complete(),"control finding was not complete");
        var model=new BoundedAgenticStream(32);
        for(int n=0;n<50000;n++) {
            if(model.append("synthetic streaming text exceeds cap"))
                cache.markSourceIncomplete();
        }
        check(model.length()==32 && model.truncated(),
            "bounded loop memory exceeded cap");
        var lost=cache.page(0,100);
        check(!lost.complete() && lost.sourceIncomplete(),
            "truncated streamed source falsely complete");
        check(lost.revision()>baseline.revision(),
            "stream loss did not invalidate earlier page revision");
        try {
            cache.page(1,100,baseline.revision());
            throw new AssertionError("stale evidence page accepted");
        } catch(IllegalStateException expected) {}
        cache.addFinding("later highly relevant","source","listing",10);
        check(cache.page(0,100).evictedCount()==1 &&
                cache.page(0,100).sourceIncomplete(),
                "pruning erased dropped-source status");
        check(cache.formatForPrompt().contains("SOURCE INCOMPLETE"),
            "review prompt omitted source-loss warning");

        for(int bad:new int[]{-1,0,BoundedAgenticStream.MAX_ITERATION_CHARS+1}) {
            try {
                new BoundedAgenticStream(bad);
                throw new AssertionError("invalid stream cap accepted: "+bad);
            } catch(IllegalArgumentException expected) {}
        }
        System.out.println("GA-15 BOUNDED MODEL STREAM INCOMPLETE PASS");
    }
}
