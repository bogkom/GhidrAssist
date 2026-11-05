package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;

public final class HardwareIndirectCallEvidenceSelfTest {
    private HardwareIndirectCallEvidenceSelfTest(){}
    private static int checks=0;
    private static void check(boolean ok,String message){
        checks++;if(!ok)throw new AssertionError(message);
    }
    private static void reject(Runnable action,String message){
        boolean denied=false;
        try{action.run();}catch(IllegalArgumentException expected){denied=true;}
        check(denied,message);
    }
    public static void main(String[] args){
        var a=new HardwareIndirectCallEvidence.Site(0x100,0x100,0x106,0x130);
        var b=new HardwareIndirectCallEvidence.Site(0x200,0x200,0x206,0x250);
        var source=HardwareIndirectCallEvidence.markdown(List.of(b,a),3,0);
        check(source.contains("| 0x00000100 | 0x00000100 | 0x00000106 | "+
                "0x00000130 | adjacent_movea_immediate |") &&
            source.contains("| 0x00000200 | 0x00000200 | 0x00000206 | "+
                "0x00000250 | adjacent_movea_immediate |"),
            "bounded source shows exact instruction and target proof");
        check(source.indexOf("| 0x00000100 |")<source.indexOf("| 0x00000200 |") &&
            source.equals(HardwareIndirectCallEvidence.markdown(
                List.of(a,b),3,0)),
            "source provenance deterministic regardless input collection order");
        check(source.contains("unresolved computed calls: 3") &&
            source.contains("NOT EXECUTION") &&
            source.contains("No other computed CALL target") &&
            source.contains("Review/Apply"),
            "unresolved remains unknown, NEVER promoted to execution/Apply");
        check(HardwareIndirectCallEvidence.markdown(List.of(),7,0)
                .contains("does NOT prove the absence"),
            "no proven target never proves absence of indirect calls");
        check(HardwareIndirectCallEvidence.markdown(List.of(a),0,2)
                .contains("INCOMPLETE DISPLAY"),
            "capped candidate display clearly marked incomplete");
        reject(()->new HardwareIndirectCallEvidence.Site(0x100,0x108,0x106,0x130),
            "initializer after JSR not a valid provenance record");
        reject(()->new HardwareIndirectCallEvidence.Site(0x100,0x100,0x106,
                0x1000000L),
            "target outside MC68332 24-bit space rejected");
        reject(()->new HardwareIndirectCallEvidence.Site(-1,0,2,0x130),
            "negative caller prohibited");
        reject(()->HardwareIndirectCallEvidence.markdown(List.of(a,a),0,0),
            "duplicate callsite cannot double-count provenance");
        reject(()->HardwareIndirectCallEvidence.markdown(List.of(a),-1,0),
            "negative unresolved count not accepted");
        reject(()->HardwareIndirectCallEvidence.markdown(List.of(a),0,-1),
            "negative omitted count not accepted");
        var many=new ArrayList<HardwareIndirectCallEvidence.Site>();
        for(int i=0;i<HardwareIndirectCallEvidence.MAX_SITES;i++)
            many.add(new HardwareIndirectCallEvidence.Site(0,0,1+i,0x130));
        check(HardwareIndirectCallEvidence.markdown(many,0,0)
                .contains("candidates displayed: "+
                    HardwareIndirectCallEvidence.MAX_SITES),
            "exact source row cap accepted");
        many.add(new HardwareIndirectCallEvidence.Site(0,0,200,0x130));
        reject(()->HardwareIndirectCallEvidence.markdown(many,0,0),
            "over-cap source rows refused before report");
        System.out.println("HardwareIndirectCallEvidenceSelfTest PASS: assertions="+checks);
    }
}
