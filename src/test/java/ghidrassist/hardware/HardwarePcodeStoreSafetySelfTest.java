package ghidrassist.hardware;

import java.util.Arrays;
import java.util.List;

public final class HardwarePcodeStoreSafetySelfTest {
    private static void ok(boolean yes,String why) {if(!yes)throw new AssertionError(why);}
    public static void main(String[] args) {
        ok(HardwarePcodeStoreSafety.uniqueTarget(List.of(0xfffa00L))==0xfffa00L,
           "one known P-code STORE can be resolved");
        ok(HardwarePcodeStoreSafety.uniqueTarget(Arrays.asList((Long)null))==null,
           "unknown P-code address remains unresolved");
        ok(HardwarePcodeStoreSafety.unknownAlias(Arrays.asList((Long)null)),
           "unknown P-code STORE must invalidate hardware constants");
        ok(HardwarePcodeStoreSafety.uniqueTarget(Arrays.asList(0xfffa00L,null))==null,
           "known plus unknown STORE cannot select the known destination");
        ok(HardwarePcodeStoreSafety.uniqueTarget(List.of(0xfffa00L,0xfffa00L))==null,
           "multiple STOREs, even to the same address, require explicit modeling");
        ok(HardwarePcodeStoreSafety.uniqueTarget(List.of())==null &&
           !HardwarePcodeStoreSafety.unknownAlias(List.of()),
           "no P-code memory writes is not an alias barrier");
        ok(HardwarePcodeStoreSafety.uniqueTarget(List.of(-1L))==null,
           "invalid constant address is not promoted");
        ok(HardwarePcodeStoreSafety.uniqueTarget(List.of(0x1000000L))==null,
           "outside 24-bit address scope is unresolved");
        System.out.println("HardwarePcodeStoreSafetySelfTest OK");
    }
}
