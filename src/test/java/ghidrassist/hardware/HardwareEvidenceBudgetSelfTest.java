package ghidrassist.hardware;

public final class HardwareEvidenceBudgetSelfTest {
    private static void ok(boolean x,String why){if(!x)throw new AssertionError(why);}
    public static void main(String[] args){
        var data=new HardwareEvidenceBudget<String>(2);
        data.offer("SIMCR");
        data.offer("CSBAR0");
        ok(!data.truncated() && data.safeAsComplete(true) &&
            data.snapshot().equals(java.util.List.of("SIMCR","CSBAR0")),
            "within budget, ordered immutable evidence");
        data.offer("UNKNOWN_ALIAS");
        ok(data.truncated() && data.omitted()==1 && data.totalSeen()==3 &&
            data.retained()==2 && !data.safeAsComplete(true),
            "truncation poisons completeness and review safety");
        ok(data.provenance().contains("does NOT prove no additional writes"),
            "no false coverage assertion after cap");
        ok(!data.safeAsComplete(false),
            "parent CFG with computed edges or truncation unknown");
        var empty=new HardwareEvidenceBudget<Integer>(4);
        ok(empty.snapshot().isEmpty() && !empty.truncated() &&
            empty.safeAsComplete(true),"zero observations are not artificial truncation");
        boolean immutable=false;
        try{data.snapshot().clear();}catch(UnsupportedOperationException e){immutable=true;}
        ok(immutable,"read-only snapshot");
        boolean invalid=false;
        try{new HardwareEvidenceBudget<Integer>(0);}catch(IllegalArgumentException e){invalid=true;}
        ok(invalid,"zero budget fails closed");
        invalid=false;
        try{data.offer(null);}catch(NullPointerException e){invalid=true;}
        ok(invalid,"null source rejected");
        System.out.println("HardwareEvidenceBudgetSelfTest OK");
    }
}
