package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Java21 test of GA-05/08 pointer identity and explicit approval policy. */
public final class HardwareScopedVariableReviewSelfTest {
    private HardwareScopedVariableReviewSelfTest() {}
    static int n;
    private static void ok(boolean condition,String detail){
        n++;if(!condition)throw new AssertionError(detail);
    }
    private static void rejects(Runnable code,String detail){
        boolean rejected=false;
        try {code.run();}catch(IllegalArgumentException expected){rejected=true;}
        ok(rejected,detail);
    }
    private static HardwareScopedVariableReview.Observation row(
            HardwareScopedVariableReview.Kind kind,int ordinal,
            String name,String storage,boolean pointer,boolean user,boolean auto){
        return new HardwareScopedVariableReview.Observation(
            0x5a0L,name,kind,ordinal,storage,pointer,user,auto);
    }
    public static void main(String[] args){
        var param=row(HardwareScopedVariableReview.Kind.PARAMETER,0,
            "param_1","stack:00000004:4",true,false,false);
        var local=row(HardwareScopedVariableReview.Kind.LOCAL,0,
            "local_4","stack:fffffff8:4",true,false,false);
        var list=HardwareScopedVariableReview.propose(List.of(param,local));
        ok(list.size()==2 &&
            list.get(0).decision()==HardwareScopedVariableReview.Decision.READY &&
            list.get(0).proposedName().equals("ga_arg_ptr_candidate_0") &&
            list.get(1).proposedName().equals("ga_local_ptr_candidate_0"),
            "only existing pointer storage produces typed placeholder names");
        ok(HardwareScopedVariableReview.recheck(
            list.get(1),local,List.of(param.currentName()))==
                HardwareScopedVariableReview.Decision.READY,
            "matching function-local reviewed identity is ready");
        ok(HardwareScopedVariableReview.recheck(
            list.get(1),local,List.of("ga_local_ptr_candidate_0"))==
                HardwareScopedVariableReview.Decision.NAME_COLLISION,
            "same function namespace collision blocks");
        ok(HardwareScopedVariableReview.recheck(list.get(1),
            row(HardwareScopedVariableReview.Kind.LOCAL,0,
                "local_4","stack:fffffff4:4",true,false,false),List.of())==
                HardwareScopedVariableReview.Decision.STALE_OR_CHANGED,
            "even unchanged name with changed storage blocks");
        ok(HardwareScopedVariableReview.recheck(list.get(0),
            row(HardwareScopedVariableReview.Kind.PARAMETER,0,
                "param_1","stack:00000004:4",false,false,false),List.of())==
                HardwareScopedVariableReview.Decision.STALE_OR_CHANGED,
            "type changes invalidate reviewed pointer evidence");
        ok(HardwareScopedVariableReview.propose(List.of(
            row(HardwareScopedVariableReview.Kind.PARAMETER,0,
                "already_named","stack:a",true,true,false))).get(0).decision()==
                HardwareScopedVariableReview.Decision.USER_NAMED,
            "manual parameter preserved");
        ok(HardwareScopedVariableReview.propose(List.of(
            row(HardwareScopedVariableReview.Kind.LOCAL,0,
                "local_8","stack:b",false,false,false))).get(0).decision()==
                HardwareScopedVariableReview.Decision.UNSUPPORTED_TYPE,
            "integer local not guessed into pointer");
        ok(HardwareScopedVariableReview.propose(List.of(
            row(HardwareScopedVariableReview.Kind.PARAMETER,0,
                "param_1","stack:c",true,false,true))).get(0).decision()==
                HardwareScopedVariableReview.Decision.UNSAFE_STORAGE,
            "implicit ABI auto/forced indirect argument blocked");
        ok(HardwareScopedVariableReview.propose(List.of(
            row(HardwareScopedVariableReview.Kind.LOCAL,0,
                "local_4","UNASSIGNED",true,false,false))).get(0).decision()==
                HardwareScopedVariableReview.Decision.UNSAFE_STORAGE,
            "unassigned storage blocked");
        ok(HardwareScopedVariableReview.propose(List.of(
            row(HardwareScopedVariableReview.Kind.LOCAL,0,
                "local_4","stack:d",true,false,false),
            row(HardwareScopedVariableReview.Kind.PARAMETER,0,
                "ga_local_ptr_candidate_0","stack:e",true,true,false)))
            .get(0).decision()==HardwareScopedVariableReview.Decision.NAME_COLLISION,
            "cross-kind name collision blocked");
        boolean immutable=false;
        try{list.clear();}catch(UnsupportedOperationException expected){immutable=true;}
        ok(immutable,"proposals are immutable");
        rejects(()->HardwareScopedVariableReview.propose(null),
            "null inventory blocks");
        rejects(()->HardwareScopedVariableReview.propose(Arrays.asList(param,null)),
            "null row blocks");
        rejects(()->HardwareScopedVariableReview.propose(List.of(local,local)),
            "duplicate same ordinal/storage identity blocks");
        rejects(()->row(HardwareScopedVariableReview.Kind.LOCAL,-1,
            "local_4","stack:x",true,false,false),
            "negative ordinal blocks");
        rejects(()->row(HardwareScopedVariableReview.Kind.LOCAL,0,
            "local_4","",true,false,false),
            "unidentified storage blocks");
        rejects(()->row(HardwareScopedVariableReview.Kind.LOCAL,0,
            "local_4","stack:x",true,false,false).functionEntry()<0 ?
            HardwareScopedVariableReview.propose(List.of()) :
            new HardwareScopedVariableReview.Observation(0x1000000L,
                "local_4",HardwareScopedVariableReview.Kind.LOCAL,0,
                "stack:x",true,false,false),
            "outside MCU24 address blocks");
        ok(HardwareScopedVariableReview.recheck(list.get(0),param,null)==
            HardwareScopedVariableReview.Decision.INVALID,
            "null current variable namespace blocks Apply");
        System.out.println("GA05 GA08 SCOPED VARIABLE POLICY PASS assertions="+n);
    }
}
