package ghidrassist.automation;

import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Bounded read-only decompilation, never performed on the Swing EDT. */
public final class AutomationDecompiler implements AutoCloseable {
    private final ExecutorService worker=Executors.newSingleThreadExecutor(r->{
        Thread t=new Thread(r,"GhidrAssist-automation-decompiler");
        t.setDaemon(true);
        return t;
    });
    private volatile String taskId="";
    private volatile String state="IDLE";
    private volatile String output="";
    private volatile String error="";
    private volatile Program source;
    private volatile long revision;
    private volatile String functionEntry="";
    private volatile boolean closed;

    public synchronized JsonObject start(Program program, Function function) {
        if(closed) throw new IllegalStateException("Decompiler closed");
        if(program==null || function==null || function.getProgram()!=program)
            throw new IllegalStateException("No active program function");
        if("RUNNING".equals(state)) throw new IllegalStateException("Decompiler already running");
        source=program;
        revision=program.getModificationNumber();
        functionEntry=function.getEntryPoint().toString();
        output=""; error=""; state="RUNNING";
        taskId=UUID.randomUUID().toString();
        final String id=taskId;
        final long expected=revision;
        worker.execute(()->{
            String text="";
            String failure="";
            DecompInterface decompiler=new DecompInterface();
            try {
                if(!decompiler.openProgram(program))
                    throw new IllegalStateException("Cannot open program in Decompiler");
                DecompileResults result=decompiler.decompileFunction(function,30,TaskMonitor.DUMMY);
                if(!result.decompileCompleted() || result.getDecompiledFunction()==null)
                    throw new IllegalStateException("Decompilation did not complete");
                text=result.getDecompiledFunction().getC();
                if(text==null) throw new IllegalStateException("Empty Decompiler result");
                // Store a bounded response. No unbounded LLM context expansion.
                if(text.length()>262144) text=text.substring(0,262144);
            }catch(Exception ex){
                failure=ex.getClass().getSimpleName()+": "+ex.getMessage();
            } finally { decompiler.dispose(); }
            synchronized(this){
                if(!taskId.equals(id) || closed)return;
                if(program.getModificationNumber()!=expected){
                    error="Program revision changed during decompilation";
                    state="STALE";
                }else if(!failure.isEmpty()){
                    error=failure;
                    state="FAILED";
                }else{
                    output=text;
                    state="COMPLETED";
                }
            }
        });
        return status(program,id,0,0);
    }

    public synchronized JsonObject status(Program activeProgram, String expectedTaskId,
                                          int offset, int limit) {
        if(offset<0 || limit<0 || limit>8192)
            throw new IllegalArgumentException("Invalid pseudocode page");
        if(expectedTaskId!=null && !expectedTaskId.isBlank() && !taskId.equals(expectedTaskId))
            throw new IllegalArgumentException("Decompiler task_id mismatch");
        JsonObject result=new JsonObject();
        result.addProperty("task_id",taskId);
        result.addProperty("state",state);
        result.addProperty("entry",functionEntry);
        // Switching the active program must never expose old pseudocode,
        // even when the two programs share the same modification number.
        if(source!=null && activeProgram!=source) {
            result.addProperty("state","STALE");
            result.addProperty("error","Active program differs from decompiler task source");
            return result;
        }
        if(source!=null && source.getModificationNumber()!=revision) {
            result.addProperty("state","STALE");
            result.addProperty("error","Program revision changed");
            return result;
        }
        result.addProperty("total_characters",output.length());
        result.addProperty("offset",offset);
        result.addProperty("limit",limit);
        result.addProperty("text",offset>=output.length() ? "" :
            output.substring(offset,Math.min(output.length(),offset+limit)));
        if(!error.isEmpty())result.addProperty("error",error);
        return result;
    }
    @Override public synchronized void close(){
        closed=true;
        worker.shutdownNow();
    }
}
