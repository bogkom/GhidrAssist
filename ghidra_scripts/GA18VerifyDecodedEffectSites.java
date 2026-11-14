// GA-01/02/03/11 genuine CPU32 decoder acceptance fixture.
// @category GhidrAssist.Tests
// Run ONLY on an isolated, disposable synthetic CPU32 program.
// Import a raw binary at 0x100 with the bytes documented below, disassemble
// 0x100..0x110 and create a single function covering all four instructions.
// Never run against ECU411 or a production Ghidra project.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidrassist.hardware.HardwareDecodedEffectSites;
import ghidrassist.hardware.HardwareGhidraEffectSiteDecoder;
import java.util.List;

public class GA18VerifyDecodedEffectSites extends GhidraScript {
    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError("GA18_DECODED_SITES_FAIL: " + message);
    }
    private Instruction at(long offset, String mnemonic) {
        Instruction ins = currentProgram.getListing().getInstructionAt(
                currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset));
        require(ins != null, "missing instruction at " + Long.toHexString(offset));
        require(mnemonic.equalsIgnoreCase(ins.getMnemonicString()),
                "unexpected mnemonic at " + Long.toHexString(offset) + ": " + ins.getMnemonicString());
        return ins;
    }
    private boolean hasStore(Instruction ins) {
        PcodeOp[] ops = ins.getPcode();
        require(ops != null, "null pcode");
        for (PcodeOp op : ops) {
            require(op != null, "null pcode op");
            if (op.getOpcode() == PcodeOp.STORE) return true;
        }
        return false;
    }
    private String register(Instruction ins, int operand) {
        Object[] objects = ins.getOpObjects(operand);
        require(objects != null && objects.length == 1 && objects[0] instanceof Register,
                "ambiguous register operand at " + ins.getAddress());
        return ((Register) objects[0]).getName();
    }
    @Override
    protected void run() throws Exception {
        require(currentProgram != null, "no program");
        require(currentProgram.getLanguageID().toString().startsWith("68000:BE:32:CPU32"),
                "fixture requires CPU32 language");
        // Raw bytes at 0x100:
        // 33 fc 40 ca 00 ff fa 00  MOVE.W #0x40ca,($00fffa00).L
        // 4e 7b 08 01              MOVEC D0,VBR
        // 4e 7a 08 01              MOVEC VBR,D0
        // 70 01                    MOVEQ #1,D0
        Instruction store = at(0x100, "MOVE.W");
        Instruction toVbr = at(0x108, "MOVEC");
        Instruction fromVbr = at(0x10c, "MOVEC");
        Instruction registerOnly = at(0x110, "MOVEQ");
        require(hasStore(store), "positive p-code STORE not decoded");
        require(!hasStore(toVbr) && !hasStore(fromVbr) && !hasStore(registerOnly),
                "negative p-code STORE control failed");
        require("VBR".equalsIgnoreCase(register(toVbr, 1)) &&
                !"VBR".equalsIgnoreCase(register(toVbr, 0)),
                "MOVEC-to-VBR decoded operand direction");
        require("VBR".equalsIgnoreCase(register(fromVbr, 0)) &&
                !"VBR".equalsIgnoreCase(register(fromVbr, 1)),
                "MOVEC-from-VBR decoded operand direction");
        HardwareDecodedEffectSites.Result result = HardwareGhidraEffectSiteDecoder.decode(currentProgram);
        require(!result.incomplete() && result.omitted() == 0,
                "decoder inventory incomplete");
        List<ghidrassist.hardware.HardwareResetEffectSites.Site> sites = result.sites();
        require(sites.size() == 2, "expected exactly STORE and MOVEC-to-VBR sites: " + sites);
        require(sites.stream().anyMatch(s -> s.instructionPc() == 0x100 &&
                s.kind() == ghidrassist.hardware.HardwareResetEffectSites.Kind.MEMORY_STORE),
                "missing STORE site");
        require(sites.stream().anyMatch(s -> s.instructionPc() == 0x108 &&
                s.kind() == ghidrassist.hardware.HardwareResetEffectSites.Kind.MOVEC_VBR),
                "missing MOVEC-to-VBR site");
        require(sites.stream().noneMatch(s -> s.instructionPc() == 0x10c || s.instructionPc() == 0x110),
                "negative MOVEC-from-VBR/register-only site included");
        println("GA18_DECODED_SITES_GHIDRA_PASS sites=2 positive=2 negative=2");
    }
}
