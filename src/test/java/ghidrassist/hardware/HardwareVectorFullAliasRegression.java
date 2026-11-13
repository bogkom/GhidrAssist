package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Source-only regression: full alias counts must not depend on display cap. */
public final class HardwareVectorFullAliasRegression {
    public static void main(String[] args) {
        List<HardwareVectorResetCorrelation.Target> targets=new ArrayList<>();
        for(int i=2;i<72;i++) {
            long entry=i<65?0x100L:0x200L;
            targets.add(new HardwareVectorResetCorrelation.Target(i,entry,entry,true));
        }
        var shortReport=HardwareVectorResetCorrelation.inspect(false,false,
            Set.of(),targets,List.of(),4);
        var longReport=HardwareVectorResetCorrelation.inspect(false,false,
            Set.of(),targets,List.of(),64);
        check(shortReport.distinctExactHandlers()==2,"short full distinct");
        check(shortReport.handlerAliasSlots()==68,"short full aliases");
        check(longReport.distinctExactHandlers()==2,"long full distinct");
        check(longReport.handlerAliasSlots()==68,"long full aliases");
        check(shortReport.displayedDistinctExactHandlers()==1,"display subset");
        check(shortReport.markdown().contains("FULL repeated exact-handler slots: 68"),"render");
        targets.add(new HardwareVectorResetCorrelation.Target(72,0x302,0x300,false));
        var interior=HardwareVectorResetCorrelation.inspect(false,false,
            Set.of(),targets,List.of(),4);
        check(interior.distinctExactHandlers()==2,"interior excluded");
        check(interior.handlerAliasSlots()==68,"interior not alias");
        try {
            new HardwareVectorResetCorrelation.Summary(false,0,false,false,
                2,2,0,0,0,false,List.of(),2,1);
            throw new AssertionError("contradictory full totals accepted");
        } catch(IllegalArgumentException expected) {}
        System.out.println("FULL VECTOR ALIAS REGRESSION PASS");
    }
    private static void check(boolean value,String message) {
        if(!value)throw new AssertionError(message);
    }
}
