// Third independent process: refused Apply must not persist changes to user memory.
// Disposable synthetic CPU32 fixture only; not a GUI Undo or physical MCU witness.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.List;

public class GA08VerifyProductionApplyAfterRefusals extends GhidraScript {
    private void require(boolean ok, String reason) {
        if (!ok) throw new IllegalStateException("GA08 POST-REFUSAL FAIL: " + reason);
    }
    @Override public void run() throws Exception {
        require(currentProgram != null && "ga08-synthetic.bin".equals(currentProgram.getName()),
                "refuse non-disposable program");
        String path = System.getProperty("ga08.test.jar");
        require(path != null && new File(path).isFile(), "production JAR missing");
        try (URLClassLoader loader = new URLClassLoader(
                new URL[]{new File(path).toURI().toURL()},
                ghidra.program.model.listing.Program.class.getClassLoader())) {
            Class<?> plan = Class.forName("ghidrassist.hardware.HardwareApplyPlan", true, loader);
            Class<?> itemType = Class.forName("ghidrassist.hardware.HardwareApplyPlan$Item", true, loader);
            Class<?> service = Class.forName("ghidrassist.hardware.HardwareApplyService", true, loader);
            List<?> candidates = (List<?>) plan.getMethod("mc68332Mm1Candidates", long.class)
                    .invoke(null, 0x1000L);
            List<Object> memory = new java.util.ArrayList<>();
            for (Object item : candidates) {
                if (itemType.getField("kind").get(item).toString().equals("MEMORY")
                        && !itemType.getField("name").get(item).equals("TPURAM_2K_CANDIDATE"))
                    memory.add(item);
            }
            require(memory.size() >= 3, "expected three module rows");
            var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
            String[] names = {
                (String) itemType.getField("name").get(memory.get(0)),
                "GA08_USER_CONFLICT", "GA08_USER_EXACT"
            };
            for (int i = 0; i < 3; i++) {
                Object item = memory.get(i);
                long address = itemType.getField("address").getLong(item);
                MemoryBlock block = currentProgram.getMemory().getBlock(space.getAddress(address));
                require(block != null && names[i].equals(block.getName()),
                        "persisted block changed after refused Apply: " + names[i]);
                require(block.getSize() == (i == 1 ? 1 : itemType.getField("length").getInt(item)),
                        "persisted block size changed: " + names[i]);
                require(!block.isInitialized() && !block.isMapped() && !block.isExecute()
                        && block.isRead() && block.isWrite(),
                        "persisted block properties changed: " + names[i]);
            }
            // Refused Apply must neither add hidden blocks nor disturb the approved module.
            int blockCount = currentProgram.getMemory().getBlocks().length;
            MemoryBlock approved = currentProgram.getMemory().getBlock(
                    space.getAddress(itemType.getField("address").getLong(memory.get(0))));
            require(approved != null, "approved module missing before refusal checks");
            var apply = service.getMethod("apply", ghidra.program.model.listing.Program.class, List.class);
            Object result = apply.invoke(null, currentProgram, List.of(memory.get(0)));
            require(result.getClass().getField("changed").getInt(result) == 0
                    && result.getClass().getField("skipped").getInt(result) == 1,
                    "approved region lost idempotence after refused Apply");
            // Re-evaluate both persisted negative controls through the production service.
            // This is a fresh process: refusal cannot depend on transient Review state.
            var preflight = service.getMethod("preflight",
                    ghidra.program.model.listing.Program.class, itemType, List.class);
            for (int i = 1; i < 3; i++) {
                Object item = memory.get(i);
                Object decision = preflight.invoke(null, currentProgram, item, candidates);
                require("BLOCKED".equals(decision.getClass().getField("state").get(decision).toString()),
                        "persisted user block no longer blocked in fresh process: " + names[i]);
                boolean refused = false;
                try {
                    apply.invoke(null, currentProgram, List.of(item));
                } catch (java.lang.reflect.InvocationTargetException failure) {
                    refused = failure.getCause() instanceof IllegalStateException;
                }
                require(refused, "fresh process accepted persisted user-owned block: " + names[i]);
                require(currentProgram.getMemory().getBlocks().length == blockCount,
                        "refused Apply changed total memory block count");
                // A refusal against one user-owned block must not mutate the OTHER
                // user-owned block either. Checking only the target would miss
                // collateral permission/name/geometry changes.
                for (int peer = 1; peer < 3; peer++) {
                    Object peerItem = memory.get(peer);
                    long peerAddress = itemType.getField("address").getLong(peerItem);
                    MemoryBlock peerBlock = currentProgram.getMemory().getBlock(
                            space.getAddress(peerAddress));
                    require(peerBlock != null && names[peer].equals(peerBlock.getName())
                            && peerBlock.getSize() == (peer == 1 ? 1 :
                                    itemType.getField("length").getInt(peerItem))
                            && !peerBlock.isInitialized() && !peerBlock.isMapped()
                            && !peerBlock.isExecute() && peerBlock.isRead() && peerBlock.isWrite(),
                            "refused Apply mutated unrelated user-owned block: " + names[peer]);
                }
                require(currentProgram.getMemory().getBlock(approved.getStart()) == approved
                        && approved.getName().equals(names[0])
                        && approved.getSize() == itemType.getField("length").getInt(memory.get(0)),
                        "refused Apply changed previously approved module");
                long address = itemType.getField("address").getLong(item);
                MemoryBlock block = currentProgram.getMemory().getBlock(space.getAddress(address));
                require(block != null && names[i].equals(block.getName())
                        && block.getSize() == (i == 1 ? 1 : itemType.getField("length").getInt(item))
                        && !block.isInitialized() && !block.isMapped() && !block.isExecute()
                        && block.isRead() && block.isWrite(),
                        "fresh process refusal mutated user block: " + names[i]);
            }
            // Negative CS-window control in the actual production preflight/Apply.
            // A synthetic CS candidate covering an executable user block must
            // fail closed; CSBAR evidence never proves physical ownership.
            Object exact = memory.get(2);
            long csAddress = itemType.getField("address").getLong(exact);
            int csLength = itemType.getField("length").getInt(exact);
            MemoryBlock csUser = currentProgram.getMemory().getBlock(space.getAddress(csAddress));
            require(csUser != null && "GA08_USER_EXACT".equals(csUser.getName()),
                    "CS negative control missing disposable user block");
            Class<?> kindType = Class.forName("ghidrassist.hardware.HardwareApplyPlan$Kind", true, loader);
            @SuppressWarnings({"unchecked", "rawtypes"})
            Object memoryKind = Enum.valueOf((Class<? extends Enum>)kindType.asSubclass(Enum.class), "MEMORY");
            var itemConstructor = itemType.getDeclaredConstructor(
                    kindType, String.class, long.class, int.class, String.class);
            itemConstructor.setAccessible(true);
            Object csCandidate = itemConstructor.newInstance(memoryKind,
                    String.format("CS_WINDOW_%06X_%06X", csAddress, csAddress + csLength - 1),
                    csAddress, csLength, "synthetic negative CS overlap; wiring UNKNOWN");
            // Snapshot every memory block, not only the three named fixtures.
            // An unsafe CS preflight/Apply must not mutate unrelated regions.
            java.util.function.Supplier<List<String>> inventory = () -> {
                List<String> rows = new java.util.ArrayList<>();
                for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
                    rows.add(b.getStart() + ":" + b.getEnd() + ":" + b.getName()
                            + ":" + b.getType() + ":" + b.isInitialized()
                            + ":" + b.isRead() + ":" + b.isWrite()
                            + ":" + b.isExecute() + ":" + b.isVolatile());
                }
                java.util.Collections.sort(rows);
                return rows;
            };
            // Baseline for every negative CS case, including unrelated blocks.
            List<String> originalInventory = inventory.get();
            // A normal R/W user-owned block must also be refused: safe-looking
            // permissions do not establish GhidrAssist ownership. Each refusal
            // must preserve the complete memory inventory and both user blocks.
            boolean originalRead = csUser.isRead();
            boolean originalWrite = csUser.isWrite();
            boolean originalExecute = csUser.isExecute();
            boolean originalVolatile = csUser.isVolatile();
            String[] permissionCases = {"benign-user-owned", "executable", "readonly", "unreadable", "volatile"};
            for (String permissionCase : permissionCases) {
                try {
                    csUser.setRead(true);
                    csUser.setWrite(true);
                    csUser.setExecute(false);
                    csUser.setVolatile(false);
                    if ("volatile".equals(permissionCase)) csUser.setVolatile(true);
                    if ("executable".equals(permissionCase)) csUser.setExecute(true);
                    if ("readonly".equals(permissionCase)) csUser.setWrite(false);
                    if ("unreadable".equals(permissionCase)) csUser.setRead(false);
                    List<String> beforeRefusal = inventory.get();
                    Object csDecision = preflight.invoke(null, currentProgram, csCandidate,
                            List.of(csCandidate));
                    require("BLOCKED".equals(csDecision.getClass().getField("state")
                            .get(csDecision).toString()),
                            permissionCase + " user CS overlap not blocked by production preflight");
                    require(inventory.get().equals(beforeRefusal),
                            "production CS preflight mutated memory inventory: " + permissionCase);
                    boolean csRefused = false;
                    try {
                        apply.invoke(null, currentProgram, List.of(csCandidate));
                    } catch (java.lang.reflect.InvocationTargetException failure) {
                        csRefused = failure.getCause() instanceof IllegalStateException;
                    }
                    require(csRefused, "production Apply accepted " + permissionCase + " CS overlap");
                    require(inventory.get().equals(beforeRefusal),
                            "rejected CS Apply changed memory inventory: " + permissionCase);
                    require(currentProgram.getMemory().getBlocks().length == blockCount
                            && currentProgram.getMemory().getBlock(space.getAddress(csAddress)) == csUser
                            && "GA08_USER_EXACT".equals(csUser.getName())
                            && csUser.getSize() == csLength
                            && csUser.isRead() == !"unreadable".equals(permissionCase)
                            && csUser.isWrite() == !"readonly".equals(permissionCase)
                            && csUser.isExecute() == "executable".equals(permissionCase)
                            && csUser.isVolatile() == "volatile".equals(permissionCase),
                            "rejected " + permissionCase + " CS Apply mutated user memory");
                    MemoryBlock peer = currentProgram.getMemory().getBlock(
                            space.getAddress(itemType.getField("address").getLong(memory.get(1))));
                    require(peer != null && "GA08_USER_CONFLICT".equals(peer.getName())
                            && peer.getSize() == 1 && peer.isRead() && peer.isWrite()
                            && !peer.isExecute() && !peer.isInitialized() && !peer.isMapped(),
                            "rejected CS Apply mutated peer user block");
                    require(currentProgram.getMemory().getBlock(approved.getStart()) == approved
                            && names[0].equals(approved.getName()),
                            "rejected CS Apply mutated approved module");
                } finally {
                    csUser.setRead(originalRead);
                    csUser.setWrite(originalWrite);
                    csUser.setExecute(originalExecute);
                    csUser.setVolatile(originalVolatile);
                }
                require(csUser.isRead() == originalRead && csUser.isWrite() == originalWrite
                        && csUser.isExecute() == originalExecute
                        && csUser.isVolatile() == originalVolatile,
                        "CS fixture permissions not restored after " + permissionCase);
                require(inventory.get().equals(originalInventory),
                        "CS refusal left collateral changes after restoration: " + permissionCase);
            }
            // A name-matching block extending beyond the proposed CS window
            // is not a reusable fragment. Even a renamed user block cannot
            // authorize adoption of memory outside the selected extent.
            require(csLength > 1, "CS boundary fixture must have multiple bytes");
            String originalName = csUser.getName();
            try {
                csUser.setName(String.format("CS_WINDOW_%06X_%06X",
                        csAddress, csAddress + csLength - 2));
                Object narrow = itemConstructor.newInstance(memoryKind, csUser.getName(),
                        csAddress, csLength - 1, "synthetic boundary negative; wiring UNKNOWN");
                List<String> beforeNarrow = inventory.get();
                Object decision = preflight.invoke(null, currentProgram, narrow, List.of(narrow));
                require("BLOCKED".equals(decision.getClass().getField("state").get(decision).toString()),
                        "CS accepted a name-matching block extending outside selected range");
                boolean rejected = false;
                try {
                    apply.invoke(null, currentProgram, List.of(narrow));
                } catch (java.lang.reflect.InvocationTargetException failure) {
                    rejected = failure.getCause() instanceof IllegalStateException;
                }
                require(rejected && inventory.get().equals(beforeNarrow),
                        "out-of-range CS block was adopted or changed");
            } finally {
                csUser.setName(originalName);
            }
            require(inventory.get().equals(originalInventory),
                    "CS boundary negative did not restore user memory");
            println("GA08 CS OUTSIDE WINDOW REFUSAL PASS: preflight=1 apply=1 restored=1");
            // A rejected CS proposal must not poison a later valid Apply.
            Object afterCs = apply.invoke(null, currentProgram, List.of(memory.get(0)));
            require(afterCs.getClass().getField("changed").getInt(afterCs) == 0
                    && afterCs.getClass().getField("skipped").getInt(afterCs) == 1
                    && inventory.get().equals(originalInventory),
                    "CS refusal poisoned approved-module idempotence or memory inventory");
            println("GA08 CS REFUSAL RECOVERY PASS: idempotent=1 inventory=1");
            // Positive counterpart: explicit selection can create an isolated,
            // previously unmapped speculative CS window. This proves the
            // negative ownership guards did not disable approved creation.
            // This is a disposable fixture, never evidence of physical decode.
            long positiveAddress = 0x00e00000L;
            int positiveLength = 0x20;
            require(currentProgram.getMemory().getBlock(space.getAddress(positiveAddress)) == null
                    && currentProgram.getMemory().getBlock(
                        space.getAddress(positiveAddress + positiveLength - 1)) == null,
                    "positive CS fixture address is occupied");
            String positiveName = String.format("CS_WINDOW_%06X_%06X",
                    positiveAddress, positiveAddress + positiveLength - 1);
            Object positiveCs = itemConstructor.newInstance(memoryKind, positiveName,
                    positiveAddress, positiveLength,
                    "explicit synthetic CS approval; physical wiring UNKNOWN");
            Object positiveDecision = preflight.invoke(null, currentProgram, positiveCs,
                    List.of(positiveCs));
            require("MANUAL_REVIEW".equals(positiveDecision.getClass().getField("state")
                    .get(positiveDecision).toString()),
                    "unmapped speculative CS was not held for explicit review");
            Object positiveResult = apply.invoke(null, currentProgram, List.of(positiveCs));
            require(positiveResult.getClass().getField("changed").getInt(positiveResult) == 1,
                    "explicitly selected synthetic CS was not created");
            MemoryBlock positiveBlock = currentProgram.getMemory().getBlock(
                    space.getAddress(positiveAddress));
            require(positiveBlock != null && positiveBlock.getSize() == positiveLength
                    && positiveBlock.getName().equals(positiveName + "_PART_1")
                    && !positiveBlock.isInitialized() && !positiveBlock.isMapped()
                    && positiveBlock.isRead() && positiveBlock.isWrite()
                    && !positiveBlock.isExecute(),
                    "approved synthetic CS fragment has unexpected properties");
            Object secondDecision = preflight.invoke(null, currentProgram, positiveCs,
                    List.of(positiveCs));
            require("ALREADY_PRESENT".equals(secondDecision.getClass().getField("state")
                    .get(secondDecision).toString()),
                    "created CS fragment is not recognized as already present");
            Object secondResult = apply.invoke(null, currentProgram, List.of(positiveCs));
            require(secondResult.getClass().getField("changed").getInt(secondResult) == 0
                    && secondResult.getClass().getField("skipped").getInt(secondResult) == 1,
                    "second CS Apply was not idempotent");
            require(currentProgram.getMemory().getBlock(space.getAddress(positiveAddress))
                    == positiveBlock && inventory.get().size() == originalInventory.size() + 1,
                    "CS positive Apply disturbed other memory");
            require(currentProgram.canSave(), "disposable project cannot save approved CS");
            currentProgram.save("GA08 approved synthetic CS persistence checkpoint", monitor);
            MemoryBlock savedCs = currentProgram.getMemory().getBlock(space.getAddress(positiveAddress));
            require(savedCs != null && savedCs.getName().equals(positiveName + "_PART_1"),
                    "approved CS disappeared after explicit save");
            println("GA08 CS EXPLICIT SAVE PASS: fragment=1");
            println("GA08 CS EXPLICIT POSITIVE APPLY PASS: review=1 created=1 idempotent=1");

            println("GA08 CS USER PERMISSION OVERLAP REFUSAL PASS: benign=1 executable=1 readonly=1 unreadable=1 volatile=1 restored=1");
            println("GA08 THIRD PROCESS NO COLLATERAL MEMORY PASS: blocks=" + blockCount);
            println("GA08 THIRD PROCESS OWNERSHIP REFUSAL PASS: conflict=1 exact=1");
            println("GA08 POST REFUSAL PERSISTENCE PASS: module=1 user_blocks=2 idempotent=1");
        }
    }
}
