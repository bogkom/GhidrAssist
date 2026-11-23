// Disposable CPU32 execution witness for Review/Apply VBR type-collision parity.
// Runs only against the GA-08 synthetic program and built production extension.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.lang.reflect.Method;
import java.util.List;

public class GA08VerifyVbrTypeCollision extends GhidraScript {
    private void check(boolean ok, String why) {
        if (!ok) throw new IllegalStateException("GA08 FAIL: " + why);
    }

    // Ghidra's DataTypeManager can retain newly added types across a Program
    // transaction rollback. Clean up only our known disposable fixture type.
    private void removeTemporaryType(CategoryPath category, String name) throws Exception {
        DataType existing = currentProgram.getDataTypeManager().getDataType(category, name);
        if (existing == null) return;
        int cleanup = currentProgram.startTransaction("GA08 remove disposable VBR type");
        boolean committed = false;
        try {
            currentProgram.getDataTypeManager().remove(existing, monitor);
            committed = true;
        } finally {
            currentProgram.endTransaction(cleanup, committed);
        }
        check(currentProgram.getDataTypeManager().getDataType(category, name) == null,
                "temporary VBR type cleanup failed");
    }

    @Override
    public void run() throws Exception {
        check(currentProgram != null && "ga08-synthetic.bin".equals(currentProgram.getName()),
                "VBR type test requires disposable synthetic program");
        String jar = System.getProperty("ga08.test.jar");
        check(jar != null && new File(jar).isFile(), "production JAR missing");
        try (URLClassLoader loader = new URLClassLoader(
                new URL[] {new File(jar).toURI().toURL()},
                ghidra.program.model.listing.Program.class.getClassLoader())) {
            Class<?> plan = Class.forName("ghidrassist.hardware.HardwareApplyPlan", true, loader);
            Class<?> itemType = Class.forName("ghidrassist.hardware.HardwareApplyPlan$Item", true, loader);
            Class<?> service = Class.forName("ghidrassist.hardware.HardwareApplyService", true, loader);
            Method candidates = plan.getMethod("mc68332Mm1Candidates", long.class);
            Method preflight = service.getMethod("preflight",
                    ghidra.program.model.listing.Program.class, itemType, List.class);
            Method apply = service.getMethod("apply",
                    ghidra.program.model.listing.Program.class, List.class);
            List<?> rows = (List<?>) candidates.invoke(null, 0x1000L);
            Object vbr = rows.stream().filter(row -> {
                try {
                    return itemType.getField("kind").get(row).toString().equals("VBR_STRUCTURE");
                } catch (Exception e) { throw new IllegalStateException(e); }
            }).findFirst().orElseThrow();
            CategoryPath category = new CategoryPath("/GhidrAssist/Hardware");
            String typeName = "CPU32_VBR_256_VECTORS";
            check(currentProgram.getDataTypeManager().getDataType(category, typeName) == null,
                    "fixture already contains VBR type");
            long address = itemType.getField("address").getLong(vbr);
            int length = itemType.getField("length").getInt(vbr);
            check(length == 1024, "expected full VBR geometry");
            var start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(address);
            check(currentProgram.getMemory().getBlock(start) == null,
                    "VBR test address must initially be unmapped");
            int tx = currentProgram.startTransaction("GA08 disposable VBR collision");
            try {
                StructureDataType wrong = new StructureDataType(category, typeName, 0);
                wrong.add(DWordDataType.dataType, 4, "wrong", null);
                currentProgram.getDataTypeManager().addDataType(
                        wrong, DataTypeConflictHandler.KEEP_HANDLER);
                Object decision = preflight.invoke(null, currentProgram, vbr, rows);
                check(decision.getClass().getField("state").get(decision).toString().equals("BLOCKED"),
                        "Review accepted conflicting existing VBR type: " + decision);
                boolean refused = false;
                try {
                    apply.invoke(null, currentProgram, List.of(vbr));
                } catch (java.lang.reflect.InvocationTargetException expected) {
                    Throwable cause = expected.getCause();
                    refused = cause instanceof IllegalStateException &&
                            cause.getMessage() != null &&
                            cause.getMessage().contains("blocked");
                }
                check(refused, "Apply accepted conflicting existing VBR type");
                check(currentProgram.getMemory().getBlock(start) == null,
                        "refused Apply mutated VBR memory");
                check(currentProgram.getDataTypeManager().getDataType(category, typeName).getLength() == 4,
                        "refused Apply replaced user-owned VBR type");
            } finally {
                currentProgram.endTransaction(tx, false);
            }
            removeTemporaryType(category, typeName);
            int positive = currentProgram.startTransaction("GA08 disposable compatible VBR");
            try {
                StructureDataType valid = new StructureDataType(category, typeName, 0);
                for (int i = 0; i < 256; i++)
                    valid.add(DWordDataType.dataType, 4, "vector_" + i, null);
                currentProgram.getDataTypeManager().addDataType(
                        valid, DataTypeConflictHandler.KEEP_HANDLER);
                currentProgram.getMemory().createUninitializedBlock(
                        "GA08_TEMP_VBR", start, length, false);
                Object decision = preflight.invoke(null, currentProgram, vbr, rows);
                check(decision.getClass().getField("state").get(decision).toString().equals("MANUAL_REVIEW"),
                        "compatible VBR type should remain manually reviewed: " + decision);
                // Explicitly remove the fixture block while its transaction is open.
                // Some headless Ghidra memory-map changes survive endTransaction(false).
                // Never remove an unknown/user-owned block: assert our exact identity.
                var temporary = currentProgram.getMemory().getBlock(start);
                check(temporary != null && "GA08_TEMP_VBR".equals(temporary.getName())
                        && temporary.getStart().equals(start) && temporary.getSize() == length,
                        "unexpected block at disposable VBR address");
                currentProgram.getMemory().removeBlock(temporary, monitor);
                check(currentProgram.getMemory().getBlock(start) == null,
                        "temporary VBR memory cleanup failed");
            } finally {
                currentProgram.endTransaction(positive, false);
            }
            check(currentProgram.getMemory().getBlock(start) == null,
                    "compatible VBR test leaked temporary memory");
            removeTemporaryType(category, typeName);
            println("GA08 VBR TYPE COLLISION RUNTIME PASS: blocked=1 compatible_review=1 rollback=2");
        }
    }
}
