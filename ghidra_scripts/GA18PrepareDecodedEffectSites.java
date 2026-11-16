// GA-01/02/03/11: prepare ONLY the disposable raw CPU32 decoder fixture.
// @category GhidrAssist.Tests
// Run after importing scripts/create-ga01-cpu32-decoder-fixture.py output
// at 0x100 into a NEW, isolated CPU32 program. Never use on ECU411.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.util.Arrays;

public class GA18PrepareDecodedEffectSites extends GhidraScript {
    private void check(boolean ok, String reason) {
        if (!ok) throw new IllegalStateException("GA18_PREPARE_FAIL: " + reason);
    }

    @Override
    protected void run() throws Exception {
        check(currentProgram != null, "no program");
        check(currentProgram.getLanguageID().toString().startsWith("68000:BE:32:CPU32"),
                "CPU32 language required");
        Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x100);
        Address end = start.add(17);
        byte[] expected = new byte[] {0x33,(byte)0xfc,0x40,(byte)0xca,0x00,
                (byte)0xff,(byte)0xfa,0x00,0x4e,0x7b,0x08,0x01,0x4e,0x7a,0x08,0x01,0x70,0x01};
        byte[] actual = new byte[18];
        check(currentProgram.getMemory().getBytes(start, actual) == 18 &&
                Arrays.equals(expected, actual), "wrong fixture bytes or import base");
        check(!currentProgram.getFunctionManager().getFunctions(true).hasNext(),
                "fixture must start without functions");
        for (int offset : new int[] {0,8,12,16}) {
            Address pc = start.add(offset);
            check(currentProgram.getListing().getInstructionAt(pc) == null,
                    "fixture must start without disassembly at " + pc);
        }
        // Disassemble each known boundary independently; fail rather than
        // silently accepting a wrong instruction length or language variant.
        int[] offsets = {0,8,12,16};
        int[] lengths = {8,4,4,2};
        for (int i = 0; i < offsets.length; i++) {
            Address pc = start.add(offsets[i]);
            check(disassemble(pc), "disassembly failed at " + pc);
            check(currentProgram.getListing().getInstructionAt(pc) != null &&
                    currentProgram.getListing().getInstructionAt(pc).getLength() == lengths[i],
                    "unexpected instruction length at " + pc);
        }
        Function function = currentProgram.getFunctionManager().createFunction(
                "GA18_DECODER_FIXTURE", start, new AddressSet(start,end),
                SourceType.USER_DEFINED);
        check(function != null && function.getBody().contains(end),
                "could not create exact fixture function");
        println("GA18_PREPARE_DECODED_SITES_PASS instructions=4 function=0x100 bytes=18");
    }
}
