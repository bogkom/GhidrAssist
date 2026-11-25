package ghidrassist.hardware;

/** Pure Java 21 regression for identity-scoped, weak GA-12 cache state. */
public final class HardwareWeakIdentityMapSelfTest {
    private static int assertions;
    private static void check(boolean passed,String explanation){
        assertions++;
        if(!passed)throw new AssertionError(explanation);
    }
    private static void rejects(Runnable action,String explanation){
        boolean refused=false;
        try{action.run();}
        catch(IllegalArgumentException expected){refused=true;}
        check(refused,explanation);
    }
    private static final class EqualOwner {
        final int id;
        EqualOwner(int id){this.id=id;}
        @Override public boolean equals(Object other){
            return other instanceof EqualOwner;
        }
        @Override public int hashCode(){return 7;}
    }
    public static void main(String[] args){
        var first=new EqualOwner(1);
        var second=new EqualOwner(2);
        var unseen=new EqualOwner(3);
        check(first!=second && first.equals(second) &&
                first.hashCode()==second.hashCode(),
            "fixtures collide by value but not Program identity");

        var completed=new HardwareWeakIdentityMap<EqualOwner,String>();
        check(completed.put(first,"cfg-a")==null &&
                completed.put(second,"cfg-b")==null,
            "different equal-valued Programs must create independent slots");
        check("cfg-a".equals(completed.get(first)) &&
                "cfg-b".equals(completed.get(second)) &&
                completed.get(unseen)==null,
            "an equal but unseen Program cannot inherit a completed CFG");
        check("cfg-a".equals(completed.put(first,"cfg-a-new")) &&
                "cfg-a-new".equals(completed.get(first)) &&
                "cfg-b".equals(completed.get(second)),
            "same exact owner refreshes only its own completed checkpoint");
        check("cfg-a-new".equals(completed.remove(first)) &&
                completed.get(first)==null &&
                "cfg-b".equals(completed.get(second)),
            "clear of one owner cannot erase another equal-valued owner");

        var skipDisk=new HardwareWeakIdentityMap<EqualOwner,Boolean>();
        skipDisk.put(first,true);
        check(Boolean.TRUE.equals(skipDisk.get(first)) &&
                skipDisk.get(second)==null && skipDisk.get(unseen)==null,
            "explicit-clear disk tombstone is Program identity scoped");
        skipDisk.put(second,false);
        check(Boolean.FALSE.equals(skipDisk.get(second)) &&
                Boolean.TRUE.equals(skipDisk.get(first)),
            "tombstone value and absence remain distinct for two owners");
        check(Boolean.TRUE.equals(skipDisk.remove(first)) &&
                skipDisk.get(first)==null &&
                Boolean.FALSE.equals(skipDisk.get(second)),
            "clearing first disk tombstone cannot change the second");
        check(completed.get(null)==null &&
                completed.remove(null)==null &&
                skipDisk.get(null)==null,
            "null lookups never alias a real Program");
        rejects(()->completed.put(null,"cfg"),
            "null owner cannot publish checkpoint evidence");
        rejects(()->completed.put(first,null),
            "null evidence cannot be stored as a completed stage");
        check(completed.put(first,"cfg-a-final")==null &&
                "cfg-a-final".equals(completed.get(first)) &&
                "cfg-b".equals(completed.get(second)),
            "new stage after clear cannot inherit another Program context");
        System.out.println("HardwareWeakIdentityMapSelfTest PASS: assertions="+assertions);
    }
}
