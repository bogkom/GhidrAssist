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
            // Three independent incompatible permission states. Each refusal
            // must preserve the complete memory inventory and both user blocks.
            boolean originalRead = csUser.isRead();
            boolean originalWrite = csUser.isWrite();
            boolean originalExecute = csUser.isExecute();
            String[] permissionCases = {"executable", "readonly", "unreadable"};
            for (String permissionCase : permissionCases) {
                try {
                    csUser.setRead(true);
                    csUser.setWrite(true);
                    csUser.setExecute(false);
                    if ("executable".equals(permissionCase)) csUser.setExecute(true);
                    if ("readonly".equals(permissionCase)) csUser.setWrite(false);
                    if ("unreadable".equals(permissionCase)) csUser.setRead(false);
                    Object csDecision = preflight.invoke(null, currentProgram, csCandidate,
                            List.of(csCandidate));
                    require("BLOCKED".equals(csDecision.getClass().getField("state")
                            .get(csDecision).toString()),
                            permissionCase + " user CS overlap not blocked by production preflight");
                    boolean csRefused = false;
                    try {
                        apply.invoke(null, currentProgram, List.of(csCandidate));
                    } catch (java.lang.reflect.InvocationTargetException failure) {
                        csRefused = failure.getCause() instanceof IllegalStateException;
                    }
                    require(csRefused, "production Apply accepted " + permissionCase + " CS overlap");
                    require(currentProgram.getMemory().getBlocks().length == blockCount
                            && currentProgram.getMemory().getBlock(space.getAddress(csAddress)) == csUser
                            && "GA08_USER_EXACT".equals(csUser.getName())
                            && csUser.getSize() == csLength
                            && csUser.isRead() == !"unreadable".equals(permissionCase)
                            && csUser.isWrite() == !"readonly".equals(permissionCase)
                            && csUser.isExecute() == "executable".equals(permissionCase),
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
                }
                require(csUser.isRead() == originalRead && csUser.isWrite() == originalWrite
                        && csUser.isExecute() == originalExecute,
                        "CS fixture permissions not restored after " + permissionCase);
            }
            println("GA08 CS USER PERMISSION OVERLAP REFUSAL PASS: executable=1 readonly=1 unreadable=1 restored=1");
            println("GA08 THIRD PROCESS NO COLLATERAL MEMORY PASS: blocks=" + blockCount);
            println("GA08 THIRD PROCESS OWNERSHIP REFUSAL PASS: conflict=1 exact=1");
            println("GA08 POST REFUSAL PERSISTENCE PASS: module=1 user_blocks=2 idempotent=1");
        }
    }
}
