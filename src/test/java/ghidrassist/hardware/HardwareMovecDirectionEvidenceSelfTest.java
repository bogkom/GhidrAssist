package ghidrassist.hardware;

import java.util.List;

public final class HardwareMovecDirectionEvidenceSelfTest {
    private static void expect(HardwareMovecDirectionEvidence.Verdict wanted,
            boolean movec, int count, List<String> source, List<String> destination,
            boolean sourceOther, boolean destinationOther) {
        var actual=HardwareMovecDirectionEvidence.classify(movec,count,
                source,destination,sourceOther,destinationOther);
        if(actual!=wanted) throw new AssertionError("MOVEC direction: expected "+
                wanted+" got "+actual);
    }
    public static void main(String[] args) {
        var yes=HardwareMovecDirectionEvidence.Verdict.TO_VBR;
        var no=HardwareMovecDirectionEvidence.Verdict.NOT_TO_VBR;
        var unknown=HardwareMovecDirectionEvidence.Verdict.UNKNOWN;
        expect(yes,true,2,List.of("D0"),List.of("VBR"),false,false);
        expect(yes,true,2,List.of("a1"),List.of("vbr"),false,false);
        expect(no,true,2,List.of("VBR"),List.of("D0"),false,false);
        expect(no,true,2,List.of("D0"),List.of("SFC"),false,false);
        expect(no,false,2,List.of("D0"),List.of("VBR"),false,false);
        expect(unknown,true,1,List.of("D0"),List.of("VBR"),false,false);
        expect(unknown,true,3,List.of("D0"),List.of("VBR"),false,false);
        expect(unknown,true,2,List.of(),List.of("VBR"),false,false);
        expect(unknown,true,2,List.of("D0"),List.of(),false,false);
        expect(unknown,true,2,List.of("D0","D1"),List.of("VBR"),false,false);
        expect(unknown,true,2,List.of("D0"),List.of("VBR","D1"),false,false);
        expect(unknown,true,2,List.of("D0"),List.of("VBR"),true,false);
        expect(unknown,true,2,List.of("D0"),List.of("VBR"),false,true);
        expect(unknown,true,2,List.of("VBR"),List.of("VBR"),false,false);
        expect(unknown,true,2,null,List.of("VBR"),false,false);
        expect(unknown,true,2,List.of("D0"),null,false,false);
        expect(unknown,true,2,List.of("D0"),List.of(" "),false,false);
        System.out.println("MOVEC_DIRECTION_SOURCE_PASS");
    }
}
