package ghidrassist.automation;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import java.util.*;

/** Read-only, bounded, direct-call static paths. Not proof of runtime execution. */
public final class AutomationCallPaths {
    private static final int MAX_FUNCTIONS = 10000;
    private static final int MAX_STEPS = 50000;
    private static final long MMIO_LOW = 0xFFF000L, MMIO_HIGH = 0xFFFFFFL;
    private AutomationCallPaths() {}

    private record Edge(Address callsite, Address target, String evidence) {}
    private record Write(Address site, Address target, String kind) {}
    private record Node(Function function, List<Edge> calls, List<Write> writes, List<Address> indirectCalls) {}
    private record Hop(Address function, Address callsite, String evidence) {}
    private record Hit(List<Hop> chain, Write write) {}
    private static final class State {
        final List<Hit> hits = new ArrayList<>();
        final Set<Address> reached = new HashSet<>();
        int steps, cycles, depthStops, unresolvedCalls;
        final Set<Address> unresolvedSites = new TreeSet<>();
        boolean budgetExceeded, hitOverflow;
    }
    private static String hex(Address a) { return a.toString(); }
    private static JsonArray addresses(Collection<Address> items) {
        JsonArray a=new JsonArray();
        for(Address item:items) a.add(hex(item));
        return a;
    }
    private static boolean isPeripheral(Address addr) {
        if(addr == null || !addr.isMemoryAddress()) return false;
        long off=addr.getOffset();
        return Long.compareUnsigned(off, MMIO_LOW)>=0 &&
               Long.compareUnsigned(off, MMIO_HIGH)<=0;
    }

    // Only the adjacent CPU32 MOVEA.L #absolute,An ; JSR (An) pattern is
    // resolved. No intervening instruction, no dataflow guess, no execution claim.
    private static Address adjacentConstantRegisterCall(Program program, Instruction call)
            throws ghidra.program.model.mem.MemoryAccessException {
        if(!"68000:BE:32:CPU32".equals(program.getLanguageID().toString())) return null;
        byte[] callBytes=call.getBytes();
        if(callBytes.length!=2) return null;
        int callOp=(callBytes[0]&255)<<8 | (callBytes[1]&255);
        if((callOp & 0xfff8)!=0x4e90) return null; // JSR (An)
        Instruction move=program.getListing().getInstructionBefore(call.getAddress());
        if(move==null || !move.getMaxAddress().next().equals(call.getAddress())) return null;
        byte[] data=move.getBytes();
        if(data.length!=6) return null;
        int moveOp=(data[0]&255)<<8 | (data[1]&255);
        if(moveOp != (0x207c | ((callOp & 7)<<9))) return null; // MOVEA.L #imm,An
        long absolute=(long)(data[2]&255)<<24 | (long)(data[3]&255)<<16 |
                      (long)(data[4]&255)<<8 | (long)(data[5]&255);
        Address target=program.getAddressFactory().getDefaultAddressSpace().getAddress(absolute);
        Function f=program.getFunctionManager().getFunctionAt(target);
        return f==null?null:f.getEntryPoint();
    }
    // Bounded straight-line proof only. Backtrack up to four decoded
    // instructions. Only CPU32 NOP and MOVEQ #imm,Dn are permitted between
    // the constant assignment and JSR (An). Both preserve all address registers;
    // any branch, unknown instruction, or register overwrite stops the proof.
    private static Address boundedConstantRegisterCall(Program program, Instruction call)
            throws ghidra.program.model.mem.MemoryAccessException {
        if(!"68000:BE:32:CPU32".equals(program.getLanguageID().toString())) return null;
        byte[] callBytes=call.getBytes();
        if(callBytes.length!=2) return null;
        int callOp=((callBytes[0]&255)<<8)|(callBytes[1]&255);
        if((callOp&0xfff8)!=0x4e90) return null;
        Instruction cursor=call;
        for(int distance=0;distance<4;distance++) {
            Instruction prev=program.getListing().getInstructionBefore(cursor.getAddress());
            if(prev==null || prev.getMaxAddress().next()==null ||
               !prev.getMaxAddress().next().equals(cursor.getAddress())) return null;
            byte[] data=prev.getBytes();
            if(data.length==2) {
                int middle=((data[0]&255)<<8)|(data[1]&255);
                // MOVEQ #signed8,Dn modifies a data register and CCR only,
                // never an address register; unlike branch opcodes it falls through.
                if(middle==0x4e71 || (middle&0xf100)==0x7000) {
                    cursor=prev;
                    continue;
                }
            }
            if(data.length!=6) return null;
            int op=((data[0]&255)<<8)|(data[1]&255);
            if(op!=(0x207c|((callOp&7)<<9))) return null;
            long address=((long)(data[2]&255)<<24)|((long)(data[3]&255)<<16)|
                         ((long)(data[4]&255)<<8)|(data[5]&255);
            Address target=program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
            Function f=program.getFunctionManager().getFunctionAt(target);
            return f==null?null:f.getEntryPoint();
        }
        return null;
    }
    private static Map<Address,Node> index(Program program)
            throws ghidra.program.model.mem.MemoryAccessException {
        Map<Address,Node> nodes=new TreeMap<>();
        var it=program.getFunctionManager().getFunctions(true);
        int totalInstructions=0;
        while(it.hasNext()) {
            if(nodes.size()>=MAX_FUNCTIONS) throw new IllegalStateException("Function index limit exceeded");
            Function f=it.next();
            List<Edge> calls=new ArrayList<>();
            List<Write> writes=new ArrayList<>();
            List<Address> indirectCalls=new ArrayList<>();
            var instructions=program.getListing().getInstructions(f.getBody(),true);
            int scanned=0;
            while(instructions.hasNext()) {
                if(++scanned>MAX_STEPS || ++totalInstructions>MAX_STEPS)
                    throw new IllegalStateException("Instruction index limit exceeded");
                Instruction ins=instructions.next();
                boolean resolvedCall=false;
                for(Reference ref:ins.getReferencesFrom()) {
                    if(ref.getReferenceType().isCall()) {
                        Function target=program.getFunctionManager().getFunctionAt(ref.getToAddress());
                        if(target!=null) {
                            calls.add(new Edge(ins.getAddress(),target.getEntryPoint(),"ghidra_call_reference"));
                            resolvedCall=true;
                        }
                    }
                    if(ref.getReferenceType().isWrite() && isPeripheral(ref.getToAddress()))
                        writes.add(new Write(ins.getAddress(),ref.getToAddress(),ref.getReferenceType().toString()));
                }
                if(ins.getFlowType().isCall() && !resolvedCall) {
                    Address proven=adjacentConstantRegisterCall(program,ins);
                    if(proven!=null) calls.add(new Edge(ins.getAddress(),proven,"adjacent_movea_immediate"));
                    else {
                        Address bounded=boundedConstantRegisterCall(program,ins);
                        if(bounded!=null) calls.add(new Edge(ins.getAddress(),bounded,"bounded_movea_safe_chain"));
                        else indirectCalls.add(ins.getAddress());
                    }
                }
            }
            calls.sort(Comparator.comparing(Edge::callsite).thenComparing(Edge::target));
            writes.sort(Comparator.comparing(Write::site).thenComparing(Write::target));
            nodes.put(f.getEntryPoint(),new Node(f,calls,writes,indirectCalls));
        }
        return nodes;
    }
    private static void walk(Address current, Map<Address,Node> nodes, int maxDepth,
                             LinkedHashSet<Address> stack, List<Hop> chain, State state) {
        if(state.budgetExceeded) return;
        if(++state.steps>MAX_STEPS) { state.budgetExceeded=true; return; }
        state.reached.add(current);
        Node node=nodes.get(current);
        if(node==null) return;
        for(Address site:node.indirectCalls) {
            state.unresolvedCalls++;
            state.unresolvedSites.add(site);
        }
        for(Write write:node.writes) {
            if(state.hits.size()<MAX_STEPS) state.hits.add(new Hit(List.copyOf(chain),write));
            else { state.hitOverflow=true; state.budgetExceeded=true; return; }
        }
        for(Edge edge:node.calls) {
            if(stack.contains(edge.target)) { state.cycles++; continue; }
            if(chain.size()-1>=maxDepth) { state.depthStops++; continue; }
            if(!nodes.containsKey(edge.target)) { state.unresolvedCalls++; continue; }
            stack.add(edge.target);
            chain.add(new Hop(edge.target,edge.callsite,edge.evidence));
            walk(edge.target,nodes,maxDepth,stack,chain,state);
            chain.remove(chain.size()-1);
            stack.remove(edge.target);
            if(state.budgetExceeded) break;
        }
    }
    public static JsonObject query(Program program, String origin, String entryText,
                                   int maxDepth, int offset, int limit) throws ghidra.program.model.mem.MemoryAccessException {
        if(program==null) throw new IllegalStateException("No active program");
        if(maxDepth<0 || maxDepth>32 || offset<0 || offset>50000 || limit<1 || limit>100)
            throw new IllegalArgumentException("Invalid paths bounds");
        Map<Address,Node> nodes=index(program);
        Address root;
        if("reset".equals(origin)) {
            Address vector=program.getAddressFactory().getDefaultAddressSpace().getAddress(4);
            if(!program.getMemory().contains(vector)) throw new IllegalStateException("Reset vector unavailable");
            long pc=Integer.toUnsignedLong(program.getMemory().getInt(vector));
            root=program.getAddressFactory().getDefaultAddressSpace().getAddress(pc);
        } else if("entry".equals(origin)) {
            if(entryText==null || entryText.isBlank()) throw new IllegalArgumentException("Entry required");
            Address requested=program.getAddressFactory().getAddress(entryText);
            Function f=requested==null?null:program.getFunctionManager().getFunctionContaining(requested);
            if(f==null) throw new IllegalArgumentException("No function at entry address");
            root=f.getEntryPoint();
        } else throw new IllegalArgumentException("origin must be reset or entry");
        if(!nodes.containsKey(root)) throw new IllegalStateException("Root function not defined");
        State state=new State();
        LinkedHashSet<Address> stack=new LinkedHashSet<>();
        stack.add(root);
        walk(root,nodes,maxDepth,stack,new ArrayList<>(List.of(new Hop(root,null,null))),state);
        JsonObject out=new JsonObject();
        out.addProperty("revision",program.getModificationNumber());
        out.addProperty("origin",origin);
        out.addProperty("root",hex(root));
        out.addProperty("max_depth",maxDepth);
        out.addProperty("offset",offset);
        out.addProperty("limit",limit);
        out.addProperty("total_paths",state.hits.size());
        out.addProperty("total_functions",nodes.size());
        out.addProperty("reachable_count",state.reached.size());
        out.addProperty("unreachable_count",nodes.size()-state.reached.size());
        out.addProperty("cycles_cut",state.cycles);
        out.addProperty("depth_cut",state.depthStops);
        out.addProperty("unresolved_calls",state.unresolvedCalls);
        out.add("unresolved_call_sites",addresses(state.unresolvedSites));
        out.addProperty("budget_exceeded",state.budgetExceeded);
        out.addProperty("complete",!state.budgetExceeded && state.depthStops==0 && state.unresolvedCalls==0);
        ArrayList<Address> reachable=new ArrayList<>(state.reached);
        ArrayList<Address> unreachable=new ArrayList<>();
        for(Address entry:nodes.keySet()) if(!state.reached.contains(entry)) unreachable.add(entry);
        Collections.sort(reachable);
        out.add("reachable_entries",addresses(reachable));
        out.add("unreachable_entries",addresses(unreachable));
        JsonArray rows=new JsonArray();
        for(int i=offset;i<Math.min((long)state.hits.size(),(long)offset+limit);i++) {
            Hit hit=state.hits.get(i);
            JsonObject row=new JsonObject();
            JsonArray functions=new JsonArray(), calls=new JsonArray(), callEvidence=new JsonArray();
            for(Hop hop:hit.chain) {
                functions.add(hex(hop.function));
                if(hop.callsite!=null) {
                    calls.add(hex(hop.callsite));
                    callEvidence.add(hop.evidence);
                }
            }
            row.add("functions",functions);
            row.add("call_sites",calls);
            row.add("call_evidence",callEvidence);
            row.addProperty("write_site",hex(hit.write.site));
            row.addProperty("mmio_target",hex(hit.write.target));
            row.addProperty("write_reference_type",hit.write.kind);
            rows.add(row);
        }
        out.add("paths",rows);
        out.addProperty("evidence","Static Ghidra CALL references and narrow CPU32 MOVEA-immediate register-call patterns and bounded straight-line NOP/MOVEQ chains; other indirect sites unresolved; no execution, MM state or physical mapping established");
        return out;
    }
}
