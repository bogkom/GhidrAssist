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
        ok(HardwarePcodeStoreSafety.oneConsistentMemoryEffect(
            1,0xfffa00L,0xfffa00L),"Listing and direct P-code agree");
        ok(HardwarePcodeStoreSafety.oneConsistentMemoryEffect(
            1,0xfffa00L,null),"one register-indirect P-code unresolved");
        ok(HardwarePcodeStoreSafety.oneConsistentMemoryEffect(
            1,null,0xfffa00L),"P-code only proven address");
        ok(HardwarePcodeStoreSafety.oneConsistentMemoryEffect(
            1,null,null),"one unknown alias is modeled, never proven");
        ok(!HardwarePcodeStoreSafety.oneConsistentMemoryEffect(
            0,0xfffa00L,null),"no P-code effect cannot endorse Listing");
        ok(!HardwarePcodeStoreSafety.oneConsistentMemoryEffect(
            -1,0xfffa00L,null),"missing P-code never proves a write");
        ok(!HardwarePcodeStoreSafety.oneConsistentMemoryEffect(
            2,0xfffa00L,0xfffa00L),"two writes must not select SIMCR");
        ok(!HardwarePcodeStoreSafety.oneConsistentMemoryEffect(
            3,null,null),"multiple unknown aliases fail closed");
        ok(!HardwarePcodeStoreSafety.oneConsistentMemoryEffect(
            1,0xfffa00L,0xfffa04L),"disagreeing P-code vs Listing refused");
        ok(!HardwarePcodeStoreSafety.oneConsistentMemoryEffect(
            64,0xfffa00L,0xfffa00L),"bounded multi-effect input refused");
        System.out.println("HardwarePcodeStoreSafetySelfTest OK");
    }
}
