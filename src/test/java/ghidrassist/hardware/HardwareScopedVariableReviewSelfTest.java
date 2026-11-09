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
        // A batched Review may contain several independent functions.
        // The same parameter ordinal, local slot and proposed name in a
        // DIFFERENT function is legal; within one function it is not.
        var fnOther=new HardwareScopedVariableReview.Observation(
            0x640L,"param_1",HardwareScopedVariableReview.Kind.PARAMETER,
            0,"stack:00000004:4",true,false,false);
        var fnOtherLocal=new HardwareScopedVariableReview.Observation(
            0x640L,"local_4",HardwareScopedVariableReview.Kind.LOCAL,
            0,"stack:fffffff8:4",true,false,false);
        var across=HardwareScopedVariableReview.propose(
            List.of(param,local,fnOther,fnOtherLocal));
        ok(across.size()==4 && across.stream().allMatch(p->
                p.decision()==HardwareScopedVariableReview.Decision.READY) &&
                across.get(0).proposedName().equals(across.get(2).proposedName()) &&
                across.get(1).proposedName().equals(across.get(3).proposedName()),
            "Same arguments/storage/names in different Functions remain independently READY");
        var alreadyNamedInOther=new HardwareScopedVariableReview.Observation(
            0x640L,"ga_arg_ptr_candidate_0",
            HardwareScopedVariableReview.Kind.PARAMETER,0,
            "stack:00000004:4",true,true,false);
        var otherName=HardwareScopedVariableReview.propose(
            List.of(param,alreadyNamedInOther));
        ok(otherName.get(0).decision()==
                HardwareScopedVariableReview.Decision.READY &&
                otherName.get(1).decision()==
                HardwareScopedVariableReview.Decision.USER_NAMED,
            "Names in another Function cannot cause a false local namespace collision");
        rejects(()->HardwareScopedVariableReview.propose(List.of(
            param,row(HardwareScopedVariableReview.Kind.PARAMETER,0,
                "param_2","stack:00000008:4",true,false,false))),
            "One Function parameter ordinal assigned to competing storages rejected");
        var changedFunction=new HardwareScopedVariableReview.Observation(
            0x640L,local.currentName(),local.kind(),local.ordinal(),
            local.storage(),true,false,false);
        ok(HardwareScopedVariableReview.recheck(list.get(1),
                changedFunction,List.of())==
                HardwareScopedVariableReview.Decision.STALE_OR_CHANGED,
            "Approval bound to Function entry cannot be replayed in another Function");
        ok(HardwareScopedVariableReview.recheck(across.get(2),fnOther,
                List.of("ga_arg_ptr_candidate_0"))==
                HardwareScopedVariableReview.Decision.NAME_COLLISION,
            "Actual current sibling Function-variable name collision still fails");
        var forged=new HardwareScopedVariableReview.Proposal(
            row(HardwareScopedVariableReview.Kind.PARAMETER,0,
                "param_1","stack:fake",false,false,false),
            "ga_arg_ptr_candidate_0",HardwareScopedVariableReview.Decision.READY);
        ok(HardwareScopedVariableReview.recheck(forged,forged.original(),List.of())==
                HardwareScopedVariableReview.Decision.INVALID,
            "public READY constructor cannot forge pointer type");
        var forgedManual=new HardwareScopedVariableReview.Proposal(
            row(HardwareScopedVariableReview.Kind.LOCAL,0,
                "my_ptr","stack:fake",true,true,false),
            "ga_local_ptr_candidate_0",HardwareScopedVariableReview.Decision.READY);
        ok(HardwareScopedVariableReview.recheck(
            forgedManual,forgedManual.original(),List.of())==
                HardwareScopedVariableReview.Decision.INVALID,
            "public READY constructor cannot override manually named variable");
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
        rejects(()->new HardwareScopedVariableReview.Observation(0x1000000L,
                "local_4",HardwareScopedVariableReview.Kind.LOCAL,0,
                "stack:x",true,false,false),
            "outside MCU24 address blocks");
        ok(HardwareScopedVariableReview.recheck(list.get(0),param,null)==
            HardwareScopedVariableReview.Decision.INVALID,
            "null current variable namespace blocks Apply");
        System.out.println("GA05 GA08 SCOPED VARIABLE POLICY PASS assertions="+n);
    }
}
