package ghidrassist.hardware;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static ghidrassist.hardware.HardwareDataflow.Kind.*;

/**
 * GA-02/03 + GA-12: source-equivalent value checks for read-only cached
 * STORE, verified post-CALL operands and MOVEC/VBR. Every fixture is a
 * synthetic CPU32 graph; a rehashed envelope is NOT authenticated evidence.
 */
public final class HardwareCheckpointValueWitnessSelfTest {
    private HardwareCheckpointValueWitnessSelfTest() {}
    private static void check(boolean yes,String why) {
        if(!yes)throw new AssertionError(why);
    }
    private static HardwareDataflow.Step step(long pc,HardwareDataflow.Kind kind,
            String reg,long literal,Integer word,int bits,long next) {
        return new HardwareDataflow.Step(pc,kind,reg,literal,0,word,bits,
            List.of(next),"synthetic");
    }
    private static HardwareDataflow.Result changed(
            HardwareDataflow.Result original,int at,
            HardwareDataflow.Snapshot replacement) {
        var sites=new ArrayList<>(original.snapshots);
        sites.set(at,replacement);
        return HardwareDataflow.Result.restore(sites,original.reachedNodes,
            original.iterations,original.knownPointersAtEntry);
    }
    private static HardwareDataflow.Snapshot edit(
            HardwareDataflow.Snapshot s,Long address,Integer word,Long vbr,
            Map<Long,Integer> peripherals) {
        return HardwareDataflow.Snapshot.restore(s.instruction,s.kind,
            address,word,s.writeBits,s.pointerRegister,vbr,peripherals,
            s.indirect,s.priorMmCandidateMin,s.priorMmCandidateMax,
            s.priorUnknownCall,s.priorUnknownStore);
    }
    private static HardwareDurableStageStore.Key project(){
        return new HardwareDurableStageStore.Key(
            HardwareDurableStageStore.hash("ga12-value-only-synthetic-program"),
            HardwareDurableStageStore.hash("ga12-value-only-synthetic-bin"),
            HardwareDurableStageStore.hash("exact-synthetic-listing-and-call"),
            HardwareDurableStageStore.hash("installed-extension-source-sha"),
            "68000:BE:32:CPU32",true);
    }
    private static HardwareDurableStageStore.Key internalKey(
            HardwareDurableStageStore.Key full,long entry,int budget,
            List<HardwareDataflow.Step> graph,Set<Long> targets)
            throws Exception {
        Method key=HardwareDurableFunctionStages.class.getDeclaredMethod("key",
            HardwareDurableStageStore.Key.class,long.class,int.class,
            java.util.Collection.class,java.util.Collection.class);
        key.setAccessible(true);
        return (HardwareDurableStageStore.Key)key.invoke(
            null,full,entry,budget,graph,targets);
    }
    private static void reject(Path dir,HardwareDurableStageStore.Key full,
            HardwareDurableStageStore.Key inner,
            List<HardwareDataflow.Step> steps,Set<Long> targets,
            HardwareDataflow.Result valid,HardwareDataflow.Result forged,
            String reason)throws Exception {
        check(!HardwareDurableFunctionStages.save(dir,full,
            0x100,400,steps,targets,forged),
            "save cannot overwrite previous source with "+reason);
        check(HardwareDurableFunctionStages.load(dir,full,
            0x100,400,steps,targets).isPresent(),
            "invalid save retains prior real source: "+reason);
        // The disk checksum/Program/Step/JAR key is deliberately valid:
        // the semantic source gate, not SHA-256 mismatch, must reject.
        HardwareDurableStageStore.save(dir,inner,
            HardwareFunctionResultCodec.encode(forged));
        check(HardwareDurableFunctionStages.load(dir,full,
            0x100,400,steps,targets).isEmpty(),
            "valid rehashed envelope cannot authenticate "+reason);
        check(HardwareDurableFunctionStages.save(dir,full,
            0x100,400,steps,targets,valid),
            "exact source evidence restores after "+reason);
    }
    public static void main(String[] args)throws Exception {
        // Two independently derived addresses: indexed A0 + D1.W*2,
        // followed by a verified post-RTS A0/D0 register pair. Neither
        // CALL nor the MMIO STORE is claimed to execute at runtime.
        var indexed=new HardwareDataflow.Step(0x104,"A0",null,"D1",
            16,2,0,0x40ca,16,List.of(0x106L),"MOVE.W #40ca,(A0,D1.W*2)");
        var callee=new HardwareDataflow.Step(0x106,CALL_BARRIER,
            null,0,0,null,0,List.of(0x10cL),"JSR leaf")
            .withSideEffects(Set.of("A0","D0","A7"))
            .withVerifiedCallReturns(Map.of("A0",0xfffa68L,"D0",0x4848L));
        var postCall=new HardwareDataflow.Step(0x10c,STORE_INDIRECT,
            "A0","D0",0,0,null,16,List.of(0x10eL),"MOVE.W D0,(A0)");
        List<HardwareDataflow.Step> steps=List.of(
            step(0x100,SET_POINTER,"A0",0xfff9fcL,null,0,0x102),
            step(0x102,SET_POINTER,"D1",2L,null,0,0x104),
            indexed,callee,postCall,
            step(0x10e,VBR_CONSTANT,null,0x5000L,null,0,0x110),
            step(0x110,SET_POINTER,"A1",0x7000L,null,0,0x112),
            step(0x112,VBR_FROM_REGISTER,"A1",0L,null,0,0x114),
            new HardwareDataflow.Step(0x114,OTHER,null,0,0,null,0,
                List.of(),"RTS"));
        Set<Long> targets=Set.of(0xfffa00L,0xfffa68L);
        var valid=HardwareDataflow.analyze(0x100,steps,targets,400);
        check(!valid.truncated && valid.snapshots.size()==4 &&
            valid.snapshots.get(0).effectiveAddress==0xfffa00L &&
            valid.snapshots.get(0).writtenWord==0x40ca &&
            valid.snapshots.get(1).effectiveAddress==0xfffa68L &&
            valid.snapshots.get(1).writtenWord==0x4848 &&
            valid.snapshots.get(2).vbr==0x5000L &&
            valid.snapshots.get(3).vbr==0x7000L,
            "Cold indexed, verified post-CALL word and two MOVEC sources");
        Path dir=Files.createTempDirectory("ga12-value-witness-");
        var full=project();
        try {
            check(HardwareDurableFunctionStages.save(dir,full,
                0x100,400,steps,targets,valid) &&
                HardwareDurableFunctionStages.load(dir,full,
                    0x100,400,steps,targets).isPresent(),
                "Actual bounded source-verified result must remain restorable");
            var key=internalKey(full,0x100,400,steps,targets);
            var idx=valid.snapshots.get(0);
            var post=valid.snapshots.get(1);
            var immVbr=valid.snapshots.get(2);
            var regVbr=valid.snapshots.get(3);
            reject(dir,full,key,steps,targets,valid,
                changed(valid,0,edit(idx,0xfffa02L,idx.writtenWord,
                    idx.vbr,idx.knownPeripheralWords)),
                "forged indexed STORE effective address");
            reject(dir,full,key,steps,targets,valid,
                changed(valid,0,edit(idx,idx.effectiveAddress,0x40cb,
                    idx.vbr,idx.knownPeripheralWords)),
                "forged immediate literal word");
            var falseMemory=new LinkedHashMap<>(idx.knownPeripheralWords);
            falseMemory.put(0xfffa00L,0x40cb);
            reject(dir,full,key,steps,targets,valid,
                changed(valid,0,edit(idx,idx.effectiveAddress,idx.writtenWord,
                    idx.vbr,falseMemory)),
                "forged 16-bit tracked MMIO after STORE");
            var extraneous=new LinkedHashMap<>(idx.knownPeripheralWords);
            extraneous.put(0xfffa02L,0x40ca);
            reject(dir,full,key,steps,targets,valid,
                changed(valid,0,edit(idx,idx.effectiveAddress,idx.writtenWord,
                    idx.vbr,extraneous)),
                "untracked peripheral key claimed as a source");
            reject(dir,full,key,steps,targets,valid,
                changed(valid,1,edit(post,post.effectiveAddress,0x4849,
                    post.vbr,post.knownPeripheralWords)),
                "forged known post-CALL D0 word");
            reject(dir,full,key,steps,targets,valid,
                changed(valid,1,edit(post,0xfffa00L,post.writtenWord,
                    post.vbr,post.knownPeripheralWords)),
                "forged known post-CALL A0 target");
            reject(dir,full,key,steps,targets,valid,
                changed(valid,2,edit(immVbr,immVbr.effectiveAddress,
                    immVbr.writtenWord,0x5002L,immVbr.knownPeripheralWords)),
                "forged MOVEC immediate VBR");
            reject(dir,full,key,steps,targets,valid,
                changed(valid,3,edit(regVbr,regVbr.effectiveAddress,
                    regVbr.writtenWord,0x7002L,regVbr.knownPeripheralWords)),
                "forged MOVEC A1 VBR");

            // Negative/unknown source: the codec cannot turn an absent
            // register proof into a known MMIO value, even if the checksum
            // is resealed and source instruction PC still matches.
            var unknown=List.of(
                step(0x100,SET_POINTER,"A0",0xfffa00L,null,0,0x102),
                new HardwareDataflow.Step(0x102,STORE_INDIRECT,
                    "A0","D0",0,0,null,16,List.of(0x104L),"MOVE.W D0,(A0)"),
                new HardwareDataflow.Step(0x104,OTHER,null,0,0,null,0,
                    List.of(),"RTS"));
            var missing=HardwareDataflow.analyze(0x100,unknown,targets,400);
            check(missing.snapshots.size()==1 &&
                missing.snapshots.get(0).writtenWord==null &&
                HardwareDurableFunctionStages.save(dir,full,
                    0x100,400,unknown,targets,missing),
                "Unknown register is a valid UNKNOWN checkpoint, not false zero");
            var m=missing.snapshots.get(0);
            var invented=changed(missing,0,edit(m,m.effectiveAddress,0x40ca,
                m.vbr,m.knownPeripheralWords));
            check(!HardwareDurableFunctionStages.save(dir,full,
                0x100,400,unknown,targets,invented),
                "UNKNOWN source register cannot gain a fictional 0x40ca literal");
            var unknownKey=internalKey(full,0x100,400,unknown,targets);
            HardwareDurableStageStore.save(dir,unknownKey,
                HardwareFunctionResultCodec.encode(invented));
            check(HardwareDurableFunctionStages.load(dir,full,
                0x100,400,unknown,targets).isEmpty(),
                "Rehashed UNKNOWN source cannot publish known MMIO value");

            // Signed 16-bit index and modulo-24 address wrap retain the
            // existing CPU32/MC68332 static formula, never a physical map.
            var signed=new HardwareDataflow.Step(0x104,"A0",null,"D1",
                16,2,0,0x40ca,16,List.of(0x106L),"indexed signed W");
            var wrapSteps=List.of(
                step(0x100,SET_POINTER,"A0",0xfffa02L,null,0,0x102),
                step(0x102,SET_POINTER,"D1",0xffffL,null,0,0x104),
                signed,
                new HardwareDataflow.Step(0x106,OTHER,null,0,0,null,0,
                    List.of(),"RTS"));
            var signedResult=HardwareDataflow.analyze(
                0x100,wrapSteps,targets,400);
            check(signedResult.snapshots.get(0).effectiveAddress==0xfffa00L &&
                HardwareDurableFunctionStages.save(dir,full,0x100,400,
                    wrapSteps,targets,signedResult) &&
                HardwareDurableFunctionStages.load(dir,full,0x100,400,
                    wrapSteps,targets).isPresent(),
                "Signed index -1 * 2 correctly resolves the same low MMIO");
            var modifiedSigned=changed(signedResult,0,edit(
                signedResult.snapshots.get(0),0xfffa04L,0x40ca,null,
                signedResult.snapshots.get(0).knownPeripheralWords));
            check(!HardwareDurableFunctionStages.save(dir,full,
                0x100,400,wrapSteps,targets,modifiedSigned),
                "Signed index cannot be laundered into a different address");
            // A direct literal STORE must preserve its encoded target and
            // word, not merely a plausible 24-bit address/16-bit number.
            var directSteps=List.of(
                new HardwareDataflow.Step(0x100,STORE_DIRECT,
                    null,0xfffa00L,0,0x40ca,16,List.of(0x102L),
                    "MOVE.W #40ca,$FFFA00"),
                new HardwareDataflow.Step(0x102,OTHER,null,0,0,null,0,
                    List.of(),"RTS"));
            var direct=HardwareDataflow.analyze(
                0x100,directSteps,targets,400);
            check(HardwareDurableFunctionStages.save(dir,full,
                    0x100,400,directSteps,targets,direct) &&
                HardwareDurableFunctionStages.load(dir,full,
                    0x100,400,directSteps,targets).isPresent(),
                "Direct literal STORE is independently source-consistent");
            var d=direct.snapshots.get(0);
            check(!HardwareDurableFunctionStages.save(dir,full,0x100,400,
                    directSteps,targets,changed(direct,0,edit(
                        d,0xfffa68L,d.writtenWord,d.vbr,
                        d.knownPeripheralWords))) &&
                !HardwareDurableFunctionStages.save(dir,full,0x100,400,
                    directSteps,targets,changed(direct,0,edit(
                        d,d.effectiveAddress,0x40cb,d.vbr,
                        d.knownPeripheralWords))),
                "Direct STORE target and immediate cannot be forged");

            // A partial byte write invalidates an overlapped full 16-bit
            // word. No previous complete constant may reappear from a
            // synthetic post-STORE checkpoint at that register.
            var partialSteps=List.of(
                step(0x100,SET_POINTER,"A0",0xfffa00L,null,0,0x102),
                new HardwareDataflow.Step(0x102,STORE_INDIRECT,
                    "A0",0,0,0xca,8,List.of(0x104L),"MOVE.B #ca,(A0)"),
                new HardwareDataflow.Step(0x104,OTHER,null,0,0,null,0,
                    List.of(),"RTS"));
            var partial=HardwareDataflow.analyze(
                0x100,partialSteps,targets,400);
            check(partial.snapshots.get(0).knownPeripheralWords.isEmpty() &&
                HardwareDurableFunctionStages.save(dir,full,0x100,400,
                    partialSteps,targets,partial),
                "Partial width leaves whole MMIO register UNKNOWN");
            var ps=partial.snapshots.get(0);
            var fakeWord=changed(partial,0,edit(ps,ps.effectiveAddress,
                ps.writtenWord,ps.vbr,Map.of(0xfffa00L,0x40ca)));
            check(!HardwareDurableFunctionStages.save(dir,full,0x100,400,
                partialSteps,targets,fakeWord),
                "Byte STORE cannot invent a known complete 16-bit register");

            // A missing A-register target clears the tracked peripheral
            // lattice; knowing the literal alone cannot authorize MMIO.
            var missingAddressSteps=List.of(
                new HardwareDataflow.Step(0x100,STORE_INDIRECT,
                    "A0",0,0,0x40ca,16,List.of(0x102L),"MOVE.W #40ca,(A0)"),
                new HardwareDataflow.Step(0x102,OTHER,null,0,0,null,0,
                    List.of(),"RTS"));
            var unresolved=HardwareDataflow.analyze(
                0x100,missingAddressSteps,targets,400);
            var u=unresolved.snapshots.get(0);
            check(u.effectiveAddress==null &&
                u.knownPeripheralWords.isEmpty() &&
                HardwareDurableFunctionStages.save(dir,full,0x100,400,
                    missingAddressSteps,targets,unresolved),
                "Unknown indirect pointer remains UNKNOWN even with literal");
            check(!HardwareDurableFunctionStages.save(dir,full,0x100,400,
                missingAddressSteps,targets,changed(unresolved,0,
                    edit(u,null,u.writtenWord,u.vbr,
                        Map.of(0xfffa00L,0x40ca)))),
                "Unknown A0 cannot fabricate complete SIMCR peripheral evidence");

            // Physical bus wiring or executing an instruction is not
            // implied by modulo-24 source arithmetic at 0xFFFFFE + 2.
            var wrapSteps24=List.of(
                step(0x100,SET_POINTER,"A0",0xfffffeL,null,0,0x102),
                step(0x102,SET_POINTER,"D1",1L,null,0,0x104),
                new HardwareDataflow.Step(0x104,"A0",null,"D1",
                    16,2,0,0x40ca,16,List.of(0x106L),
                    "modulo24 indexed source"),
                new HardwareDataflow.Step(0x106,OTHER,null,0,0,null,0,
                    List.of(),"RTS"));
            var wrap=HardwareDataflow.analyze(
                0x100,wrapSteps24,Set.of(0L),400);
            check(wrap.snapshots.get(0).effectiveAddress==0L &&
                HardwareDurableFunctionStages.save(dir,full,0x100,400,
                    wrapSteps24,Set.of(0L),wrap) &&
                HardwareDurableFunctionStages.load(dir,full,0x100,400,
                    wrapSteps24,Set.of(0L)).isPresent(),
                "Modulo24 source calculation remains consistent at wrap boundary");
            System.out.println(
                "HardwareCheckpointValueWitnessSelfTest OK: synthetic read-only source");
        }finally {
            try(var entries=Files.list(dir)) {
                for(Path p:entries.toList())Files.deleteIfExists(p);
            }
            Files.deleteIfExists(dir);
        }
    }
}
