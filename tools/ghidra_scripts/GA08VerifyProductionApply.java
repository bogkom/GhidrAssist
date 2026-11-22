// Genuine disposable Ghidra 12.1.4 headless witness for the production Apply service.
// Requires -Dga08.test.jar=<built extension jar> and a synthetic CPU32 program.
// This script is not a replacement for UI Review authorization or formal GA-08.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.lang.reflect.Method;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;

public class GA08VerifyProductionApply extends GhidraScript {
    private void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException("GA08 FAIL: " + message);
    }

    // Full-memory witness: a refused batch must not mutate unrelated user regions.
    private List<String> inventory() {
        List<String> entries = new ArrayList<>();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            entries.add(block.getStart() + ".." + block.getEnd() + "|" + block.getName()
                    + "|" + block.getType() + "|" + block.isInitialized()
                    + "|" + block.isRead() + "|" + block.isWrite()
                    + "|" + block.isExecute() + "|" + block.isVolatile());
        }
        Collections.sort(entries);
        return entries;
    }

    // Include initialized bytes and all user symbols: memory geometry alone
    // cannot detect a refused Apply silently rewriting existing program data.
    private String contentFingerprint() throws Exception {
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isInitialized()) continue;
            long remaining = block.getSize();
            var address = block.getStart();
            byte[] bytes = new byte[4096];
            while (remaining > 0) {
                int count = (int) Math.min(remaining, bytes.length);
                int read = currentProgram.getMemory().getBytes(address, bytes, 0, count);
                require(read == count, "short initialized memory read");
                digest.update(bytes, 0, count);
                remaining -= count;
                address = address.add(count);
            }
        }
        java.util.List<String> symbols = new java.util.ArrayList<>();
        var iterator = currentProgram.getSymbolTable().getAllSymbols(true);
        while (iterator.hasNext()) {
            var symbol = iterator.next();
            symbols.add(symbol.getAddress() + "|" + symbol.getName() + "|"
                    + symbol.getSource() + "|" + symbol.getSymbolType());
        }
        java.util.Collections.sort(symbols);
        for (String symbol : symbols) {
            digest.update(symbol.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            digest.update((byte) 0);
        }
        return java.util.HexFormat.of().formatHex(digest.digest());
    }

    @Override
    public void run() throws Exception {
        String path = System.getProperty("ga08.test.jar");
        require(path != null && new File(path).isFile(), "built production extension JAR missing");
        require(currentProgram != null, "synthetic program missing");
        require("ga08-synthetic.bin".equals(currentProgram.getName()),
                "refuse to run production Apply witness outside disposable fixture");
        URL jar = new File(path).toURI().toURL();
        // Anchor delegation to Ghidra's API loader, not the script compilation loader.
        // The latter may not resolve transitive classes used by the production JAR.
        try (URLClassLoader loader = new URLClassLoader(new URL[] {jar},
                ghidra.program.model.listing.Program.class.getClassLoader())) {
            Class<?> plan = Class.forName("ghidrassist.hardware.HardwareApplyPlan", true, loader);
            Class<?> itemType = Class.forName("ghidrassist.hardware.HardwareApplyPlan$Item", true, loader);
            Class<?> service = Class.forName("ghidrassist.hardware.HardwareApplyService", true, loader);
            Method candidates = plan.getMethod("mc68332Mm1Candidates", long.class);
            Method apply = service.getMethod("apply",
                    ghidra.program.model.listing.Program.class, List.class);
            List<?> items = (List<?>) candidates.invoke(null, 0x1000L);
            Object first = items.stream().filter(item -> {
                try {
                    Object kind = itemType.getField("kind").get(item);
                    return kind.toString().equals("MEMORY")
                        && !itemType.getField("name").get(item).equals("TPURAM_2K_CANDIDATE");
                } catch (Exception ex) { throw new IllegalStateException(ex); }
            }).findFirst().orElseThrow();
            long address = itemType.getField("address").getLong(first);
            int length = itemType.getField("length").getInt(first);
            String name = (String) itemType.getField("name").get(first);
            var at = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(address);
            require(currentProgram.getMemory().getBlock(at) == null,
                    "fixture must not pre-map the module");
            Object second = items.stream().filter(item -> {
                try {
                    return itemType.getField("kind").get(item).toString().equals("MEMORY")
                        && itemType.getField("address").getLong(item) != address
                        && !itemType.getField("name").get(item).equals("TPURAM_2K_CANDIDATE");
                } catch (Exception ex) { throw new IllegalStateException(ex); }
            }).findFirst().orElseThrow();
            long other = itemType.getField("address").getLong(second);
            var otherAt = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(other);
            // User-owned controls were committed by the preceding setup script.
            require(currentProgram.getMemory().getBlock(otherAt)!=null &&
                    "GA08_USER_CONFLICT".equals(currentProgram.getMemory().getBlock(otherAt).getName()),
                    "independent conflict fixture missing");
            Object exact = items.stream().filter(item -> {
                try {
                    return itemType.getField("kind").get(item).toString().equals("MEMORY")
                        && itemType.getField("address").getLong(item) != address
                        && itemType.getField("address").getLong(item) != other
                        && !itemType.getField("name").get(item).equals("TPURAM_2K_CANDIDATE");
                } catch(Exception ex){throw new IllegalStateException(ex);}
            }).findFirst().orElseThrow();
            long exactOffset=itemType.getField("address").getLong(exact);
            var exactAt=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(exactOffset);
            require(currentProgram.getMemory().getBlock(exactAt)!=null &&
                    "GA08_USER_EXACT".equals(currentProgram.getMemory().getBlock(exactAt).getName()),
                    "independent exact fixture missing");
            List<String> beforeRefusals = inventory();
            String beforeContent = contentFingerprint();
            boolean exactRejected = false;
            try {
                apply.invoke(null, currentProgram, List.of(exact));
            } catch (java.lang.reflect.InvocationTargetException expected) {
                exactRejected = expected.getCause() instanceof IllegalStateException
                        && expected.getCause().getMessage().contains("blocked");
            }
            require(exactRejected, "exact user-owned module must be BLOCKED");
            require(currentProgram.getMemory().getBlock(exactAt).getName()
                    .equals("GA08_USER_EXACT"), "exact user block changed");
            require(beforeRefusals.equals(inventory()),
                    "exact user-owned refusal changed the complete MEMORY inventory");
            require(beforeContent.equals(contentFingerprint()),
                    "exact refusal altered initialized bytes or symbols");
            println("GA08 EXACT USER BLOCK REFUSAL PASS: preserved=1");
            boolean rejected = false;
            try {
                apply.invoke(null, currentProgram, List.of(first, second));
            } catch (java.lang.reflect.InvocationTargetException expected) {
                rejected = expected.getCause() instanceof IllegalStateException
                    && expected.getCause().getMessage().contains("blocked");
            }
            require(rejected, "conflicting approved row must reject the whole batch");
            require(currentProgram.getMemory().getBlock(at) == null,
                    "earlier approved region survived a failed transaction");
            require(currentProgram.getMemory().getBlock(otherAt).getName()
                    .equals("GA08_USER_CONFLICT"), "user block changed on rollback");
            require(beforeRefusals.equals(inventory()),
                    "stale-conflict refusal changed the complete MEMORY inventory");
            require(beforeContent.equals(contentFingerprint()),
                    "mixed refusal altered initialized bytes or symbols");
            println("GA08 REFUSED APPLY CONTENT INTEGRITY PASS: exact=1 mixed=1");
            // Runtime regression for ambiguous MEMORY approvals. These are
            // deliberately synthetic Review rows, not discovered MCU regions.
            // Duplicate, partial intersection and containment must all fail
            // before the first approved memory write.
            java.lang.reflect.Constructor<?> itemConstructor =
                    itemType.getDeclaredConstructor(
                        Class.forName("ghidrassist.hardware.HardwareApplyPlan$Kind", true, loader),
                        String.class, long.class, int.class, String.class);
            itemConstructor.setAccessible(true);
            Object memoryKind = itemType.getField("kind").get(first);
            Object[] overlapping = {
                itemConstructor.newInstance(memoryKind, "GA08_DUPLICATE", address,
                        length, "synthetic duplicate"),
                itemConstructor.newInstance(memoryKind, "GA08_PARTIAL",
                        address + length - 1, 2, "synthetic boundary intersection"),
                itemConstructor.newInstance(memoryKind, "GA08_CONTAINED",
                        address, 1, "synthetic contained range")
            };
            int overlapRejected = 0;
            // Both approval orders matter: a conflict must be rejected before
            // the first write regardless of which row Review presents first.
            for (Object conflicting : overlapping) {
                for (boolean reverse : new boolean[] {false, true}) {
                    List<?> selection = reverse
                            ? List.of(conflicting, first) : List.of(first, conflicting);
                    boolean refused = false;
                    try {
                        apply.invoke(null, currentProgram, selection);
                    } catch (java.lang.reflect.InvocationTargetException expected) {
                        Throwable cause = expected.getCause();
                        refused = cause instanceof IllegalStateException
                                && cause.getMessage() != null
                                && cause.getMessage().contains("overlapping MEMORY approvals");
                    }
                    require(refused, "ambiguous MEMORY pair was not rejected; reverse=" + reverse);
                    require(currentProgram.getMemory().getBlock(at) == null,
                            "ambiguous approval created the first MEMORY region");
                    require(beforeRefusals.equals(inventory()),
                            "ambiguous approval changed the complete MEMORY inventory");
                    require(beforeContent.equals(contentFingerprint()),
                            "ambiguous approval changed initialized bytes or symbols");
                    overlapRejected++;
                }
            }
            println("GA08 OVERLAPPING MEMORY RUNTIME REFUSAL PASS: cases=" + overlapRejected);
            // Independently verify register ownership collision rejection before
            // any MEMORY writes. Exercise both approval orders, including an
            // identical row and a partially intersecting register span.
            Object registerKind = items.stream().filter(item -> {
                try {
                    return itemType.getField("kind").get(item).toString().equals("REGISTER");
                } catch (Exception ex) { throw new IllegalStateException(ex); }
            }).map(item -> {
                try { return itemType.getField("kind").get(item); }
                catch (Exception ex) { throw new IllegalStateException(ex); }
            }).findFirst().orElseThrow();
            Object regA = itemConstructor.newInstance(registerKind,
                    "GA08_REGISTER_A", address + 8, 2, "synthetic register");
            Object[] registerConflicts = {
                itemConstructor.newInstance(registerKind,
                        "GA08_REGISTER_DUPLICATE", address + 8, 2, "duplicate register"),
                itemConstructor.newInstance(registerKind,
                        "GA08_REGISTER_PARTIAL", address + 9, 2, "intersecting register"),
                itemConstructor.newInstance(registerKind,
                        "GA08_REGISTER_CONTAINED", address + 8, 1, "contained register"),
                itemConstructor.newInstance(registerKind,
                        "GA08_REGISTER_CONTAINING", address + 7, 4, "containing register")
            };
            int registerRejected = 0;
            for (Object conflict : registerConflicts) {
                for (boolean reverse : new boolean[] {false, true}) {
                    List<?> selection = reverse
                            ? List.of(first, conflict, regA) : List.of(first, regA, conflict);
                    boolean refused = false;
                    try {
                        apply.invoke(null, currentProgram, selection);
                    } catch (java.lang.reflect.InvocationTargetException expected) {
                        Throwable cause = expected.getCause();
                        refused = cause instanceof IllegalStateException
                                && cause.getMessage() != null
                                && cause.getMessage().contains("overlapping REGISTER approvals");
                    }
                    require(refused, "ambiguous REGISTER pair not rejected; reverse=" + reverse);
                    require(beforeRefusals.equals(inventory()),
                            "REGISTER collision altered memory inventory");
                    require(beforeContent.equals(contentFingerprint()),
                            "REGISTER collision altered bytes or symbols");
                    registerRejected++;
                }
            }
            println("GA08 OVERLAPPING REGISTER RUNTIME REFUSAL PASS: cases=" + registerRejected);
            // Cross-kind collision: a register cannot be approved over the
            // same bytes as a VBR structure, regardless of Review order.
            Object vbrCollision = items.stream().filter(item -> {
                try {
                    return itemType.getField("kind").get(item).toString().equals("VBR_STRUCTURE");
                } catch (Exception ex) { throw new IllegalStateException(ex); }
            }).findFirst().orElseThrow();
            long vectorBase = itemType.getField("address").getLong(vbrCollision);
            Object vectorRegister = itemConstructor.newInstance(registerKind,
                    "GA08_VECTOR_REGISTER", vectorBase + 4, 2, "synthetic VBR collision");
            int crossKindRejected = 0;
            for (boolean reverse : new boolean[] {false, true}) {
                List<?> selection = reverse
                        ? List.of(first, vbrCollision, vectorRegister)
                        : List.of(first, vectorRegister, vbrCollision);
                boolean refused = false;
                try {
                    apply.invoke(null, currentProgram, selection);
                } catch (java.lang.reflect.InvocationTargetException expected) {
                    Throwable cause = expected.getCause();
                    refused = cause instanceof IllegalStateException
                            && cause.getMessage() != null
                            && cause.getMessage().contains("ambiguous REGISTER/VBR approvals");
                }
                require(refused, "REGISTER/VBR collision not refused; reverse=" + reverse);
                require(currentProgram.getMemory().getBlock(at) == null,
                        "REGISTER/VBR refusal created a MEMORY region");
                require(beforeRefusals.equals(inventory()),
                        "REGISTER/VBR refusal changed memory inventory");
                require(beforeContent.equals(contentFingerprint()),
                        "REGISTER/VBR refusal changed bytes or symbols");
                crossKindRejected++;
            }
            println("GA08 REGISTER VBR COLLISION REFUSAL PASS: cases=" + crossKindRejected);



            println("GA08 PRODUCTION APPLY ROLLBACK PASS: stale_conflict=1 prior_mutations=0");
            // Genuine transaction rollback: MEMORY is created first, then the
            // deliberately unmapped VBR row is rejected in the later kind pass.
            // Unlike the preflight conflict above, this must undo a real write.
            Object vbr = items.stream().filter(item -> {
                try {
                    return itemType.getField("kind").get(item).toString().equals("VBR_STRUCTURE");
                } catch (Exception ex) { throw new IllegalStateException(ex); }
            }).findFirst().orElseThrow();
            long vbrAddress = itemType.getField("address").getLong(vbr);
            var vbrAt = currentProgram.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(vbrAddress);
            require(currentProgram.getMemory().getBlock(vbrAt) == null,
                    "VBR negative control must be unmapped");
            boolean lateRejected = false;
            try {
                apply.invoke(null, currentProgram, List.of(first, vbr));
            } catch (java.lang.reflect.InvocationTargetException expected) {
                lateRejected = expected.getCause() instanceof IllegalStateException
                    && expected.getCause().getMessage().contains("blocked");
            }
            require(lateRejected, "late VBR conflict must reject a partially written batch");
            // GhidraScript owns an outer transaction. Nested service rollback is
            // not observable until this script returns and its outer transaction ends.
            // A separate postScript verifies the persisted state, then applies
            // the positive case. Never print a rollback PASS here.
            println("GA08 LATE ROLLBACK REQUESTED: verify in next script");
        }
    }
}
