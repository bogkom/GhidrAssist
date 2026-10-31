package ghidrassist.hardware;

import java.util.List;

/** Guard against reintroducing a full-register Analyze dump. */
public final class HardwareReportScopeSelfTest {
    private static void check(String s,boolean expected) {
        if(HardwareReportScope.isInitializationRegister(s)!=expected)
            throw new AssertionError("Unexpected Analyze visibility for " + s);
    }
    public static void main(String[] args) {
        for(String s:List.of("SIMCR","TRAMBAR","CSBARBT","CSORBT",
                "CSBAR0","CSOR0","CSBAR7","CSOR7","CSBAR10","CSOR10"))
            check(s,true);
        for(String s:List.of("SYNCR","SYPCR","SWSR","QSMCR","TPUMCR",
                "CSPAR0","CSPAR1","PEPAR","PORTF0","CSBAR11","CSOR11"))
            check(s,false);
        check(null,false);
        var review=HardwareApplyPlan.mc68332Mm1Candidates(0).stream()
            .filter(x->x.kind==HardwareApplyPlan.Kind.REGISTER).toList();
        if(review.size()<100 || review.stream().noneMatch(
                x->!HardwareReportScope.isInitializationRegister(x.name)))
            throw new AssertionError("Review / Apply must retain all source-backed registers");
        System.out.println("HardwareReportScopeSelfTest: PASS, register definitions="+review.size());
    }
}
