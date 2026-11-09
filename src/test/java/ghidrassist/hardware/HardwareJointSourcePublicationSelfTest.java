package ghidrassist.hardware;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Deterministic exact-revision atomic GA-12/18 joint-source publication. */
public final class HardwareJointSourcePublicationSelfTest {
    private static int checks;
    private static void check(boolean b,String name) {
        checks++;
        if(!b)throw new AssertionError(name);
    }
    private static void stale(Runnable action,String name) {
        boolean blocked=false;
        try { action.run(); }
        catch(HardwareJointSourcePublication.StaleRevision expected) {
            blocked="STALE_REVISION".equals(expected.getMessage());
        }
        check(blocked,name);
    }
    public static void main(String[] args) {
        Object program=new Object(),different=new Object();
        AtomicInteger renderCount=new AtomicInteger();
        AtomicBoolean epoch=new AtomicBoolean(true);
        AtomicReference<HardwareAnalysisRevision> live=new AtomicReference<>(
            HardwareAnalysisRevision.capture(program,4,"68000:BE:32:CPU32",
                "original-synthetic-sha",true));
        var captured=live.get();
        String sensitive="| 0x00000130 | 0x00000138 | 0x00000144 | STATIC_MAY_MM |";
        var current=(java.util.function.Supplier<HardwareAnalysisRevision>)live::get;
        var stages=(java.util.function.BooleanSupplier)epoch::get;
        String accepted=HardwareJointSourcePublication.render(
            captured,current,stages,()->{
                renderCount.incrementAndGet();return sensitive;
            });
        check(accepted.equals(sensitive) && renderCount.get()==1,
            "Same current Program, SHA, profile, epoch publishes only full text");

        live.set(HardwareAnalysisRevision.capture(program,5,
            "68000:BE:32:CPU32","original-synthetic-sha",true));
        stale(()->HardwareJointSourcePublication.render(
            captured,current,stages,()->{
                renderCount.incrementAndGet();return sensitive;
            }),"Edit/Undo/Redo revision rejects prior candidate before rendering");
        check(renderCount.get()==1,"Entry guard never starts stale renderer");

        live.set(HardwareAnalysisRevision.capture(different,4,
            "68000:BE:32:CPU32","original-synthetic-sha",true));
        stale(()->HardwareJointSourcePublication.render(captured,current,
            stages,()->sensitive),"Different live Program identity rejected");

        live.set(HardwareAnalysisRevision.capture(program,4,
            "68000:BE:32:CPU32","changed-source-sha",true));
        stale(()->HardwareJointSourcePublication.render(captured,current,
            stages,()->sensitive),"Changed imported executable SHA rejected");

        live.set(HardwareAnalysisRevision.capture(program,4,
            "68000:BE:32:68020","original-synthetic-sha",true));
        stale(()->HardwareJointSourcePublication.render(captured,current,
            stages,()->sensitive),"Changed language rejects metadata");

        live.set(HardwareAnalysisRevision.capture(program,4,
            "68000:BE:32:CPU32","original-synthetic-sha",false));
        stale(()->HardwareJointSourcePublication.render(captured,current,
            stages,()->sensitive),"Generic CPU32 cannot reuse selected MCU report");

        live.set(captured);
        epoch.set(false);
        stale(()->HardwareJointSourcePublication.render(captured,current,
            stages,()->sensitive),"Explicit stage invalidation refuses same revision");
        epoch.set(true);

        stale(()->HardwareJointSourcePublication.render(captured,current,
            stages,()->{
                live.set(HardwareAnalysisRevision.capture(program,6,
                    "68000:BE:32:CPU32","original-synthetic-sha",true));
                return sensitive;
            }),"Late edit after all source rows but before return erases entire output");
        live.set(captured);
        stale(()->HardwareJointSourcePublication.render(captured,current,
            stages,()->{
                epoch.set(false);
                return sensitive;
            }),"Stage clear during publication refuses all candidate rows");
        epoch.set(true);

        stale(()->HardwareJointSourcePublication.render(captured,current,
            stages,()->{
                live.set(HardwareAnalysisRevision.capture(program,4,
                    "68000:BE:32:CPU32","changed-source-sha",true));
                return sensitive;
            }),"Live source identity changes at publication exit");
        live.set(captured);
        stale(()->HardwareJointSourcePublication.render(captured,current,
            stages,()->{
                live.set(HardwareAnalysisRevision.capture(program,4,
                    "68000:BE:32:CPU32","original-synthetic-sha",false));
                return sensitive;
            }),"Profile transition at publication exit");
        live.set(captured);

        AtomicInteger calls=new AtomicInteger();
        stale(()->HardwareJointSourcePublication.render(captured,
            ()->{if(calls.incrementAndGet()==2)
                live.set(HardwareAnalysisRevision.capture(program,7,
                    "68000:BE:32:CPU32","original-synthetic-sha",true));
                return live.get();},stages,()->sensitive),
            "Deterministic two-check race discards already rendered source");
        live.set(captured);
        try { HardwareJointSourcePublication.render(captured,current,stages,null);
            throw new AssertionError("missing renderer accepted");
        } catch(IllegalArgumentException expected) { checks++; }
        try { HardwareJointSourcePublication.render(captured,current,stages,()->null);
            throw new AssertionError("missing report accepted");
        } catch(IllegalArgumentException expected) { checks++; }
        stale(()->HardwareJointSourcePublication.requireCurrent(
            null,current,stages),"Missing snapshot never authorizes publishing");
        System.out.println("HardwareJointSourcePublicationSelfTest PASS: assertions="+checks);
    }
}
