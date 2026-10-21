package ghidrassist.hardware;

/**
 * Dependency-free sanity checks for profile metadata and CSBAR arithmetic.
 *
 * To run independently of Ghidra:
 * javac -d /tmp/hwcheck src/main/java/ghidrassist/hardware/HardwareProfiles.java \
 *     src/test/java/ghidrassist/hardware/HardwareProfilesSelfTest.java
 * java -cp /tmp/hwcheck ghidrassist.hardware.HardwareProfilesSelfTest
 */
public final class HardwareProfilesSelfTest {
    private HardwareProfilesSelfTest() {}

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        HardwareProfiles.Profile cpu = HardwareProfiles.select("CPU32");
        check(!cpu.concreteDevice && cpu.registers.isEmpty(),
            "CPU32 ISA must not be mistaken for MC68332 register map");
        HardwareProfiles.Profile m = HardwareProfiles.select("MC68332");
        check(m.concreteDevice, "MC68332 selection required");
        check(m.absoluteAddress(m.register("SIMCR"), 0) == 0x7ffa00L, "SIMCR MM0");
        check(m.absoluteAddress(m.register("SIMCR"), 1) == 0xfffa00L, "SIMCR MM1");
        check(m.absoluteAddress(m.register("CSBAR0"), 1) == 0xfffa4cL, "CSBAR0");
        check(m.absoluteAddress(m.register("CSBAR10"), 1) == 0xfffa74L, "CSBAR10");
        check(m.absoluteAddress(m.register("TRAMMCR"),1) == 0xfffb00L, "TRAMMCR");
        check(m.absoluteAddress(m.register("TRAMBAR"),1) == 0xfffb04L, "TRAMBAR");
        check(m.absoluteAddress(m.register("QSMCR"),1) == 0xfffc00L, "QSMCR");
        check(m.absoluteAddress(m.register("TPUMCR"),1) == 0xfffe00L, "TPUMCR");
        check(cpu.modules.isEmpty(), "CPU32 must not inherit MC68332 modules");
        check(m.modules.size() == 4, "four source-backed D-1 apertures");
        long[] expectedBases = {0xfffa00L, 0xfffb00L, 0xfffc00L, 0xfffe00L};
        int[] expectedSizes = {128, 64, 512, 512};
        for (int i = 0; i < m.modules.size(); i++) {
            var region = m.modules.get(i);
            check(region.offset+HardwareProfiles.INTERNAL_BASE_MM1 == expectedBases[i] &&
                region.sizeBytes == expectedSizes[i], "D-1 module " + region.id);
            check(region.sourcePage.contains("PDF page 215"),
                "source-page evidence required");
        }
        var simcr = m.register("SIMCR");
        check(simcr.access == HardwareProfiles.Access.SUPERVISOR &&
            simcr.resetValue == null, "do not fabricate SIMCR reset value");
        check(simcr.fields.stream().anyMatch(x->x.name.equals("MM") &&
            x.mask == HardwareProfiles.MM_MASK && x.writeOnceAfterReset &&
            x.resetValue == null), "MM mask and write-once semantics");
        check(simcr.fields.stream().anyMatch(x->x.name.equals("IARB") &&
            x.mask == 0x000f && x.resetValue == 0x000f),
            "IARB reset nibble from D-6");
        check(m.absoluteAddress(m.register("RSR"),1) == 0xfffa07L &&
            m.register("RSR").widthBits==8 &&
            m.register("RSR").writePolicy==HardwareProfiles.WritePolicy.READ_ONLY,
            "RSR occupies the odd byte and is read-only");
        check(m.absoluteAddress(m.register("PICR"),1) == 0xfffa22L &&
            m.absoluteAddress(m.register("PITR"),1)==0xfffa24L,
            "D-4 PICR and PITR");
        for (var r : m.registers) {
            check(r.sourcePage != null && !r.sourcePage.isBlank(),
                "register missing source-page uncertainty metadata");
            check(r.resetValue == null, "unknown register reset is not zero");
        }
        HardwareProfiles.CsbarWindow a = HardwareProfiles.decodeCsbar(0xfff8);
        check(a.base == 0xfff800L && a.size == 2048 && a.endInclusive == 0xffffffL,
            "2 KiB CSBAR window");
        HardwareProfiles.CsbarWindow b = HardwareProfiles.decodeCsbar(0x2003);
        check(b.base == 0x200000L && b.size == 65536 && b.endInclusive == 0x20ffffL,
            "64 KiB CSBAR window");
        HardwareProfiles.CsbarWindow c = HardwareProfiles.decodeCsbar(0x0007);
        check(c.base == 0 && c.size == 1048576, "1 MiB CSBAR window");
        boolean rejected = false;
        try {
            HardwareProfiles.select("MC68336");
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }
        check(rejected, "Unknown device must not be silently treated as MC68332");
        System.out.println("HardwareProfilesSelfTest OK");
    }
}
