// Export a Ghidra evidence summary for local RAG indexing and manual naming review.
// Standalone: no GhidrAssist extension classes. Never writes to the Ghidra project.
//@category GhidrAssist.Hardware

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Generates a locally saved, readable evidence report and name proposals.
 * The CSV is NOT a batch label-application file: it is review-only.
 */
public class GhidrAssist_Export_Hardware_Context extends GhidraScript {
    private static class Candidate {
        final String device,family,register;
        final long address;
        Candidate(String d,String f,String r,long a){device=d;family=f;register=r;address=a;}
    }
    private static List<Candidate> catalog(File scriptFile)throws Exception {
        List<Candidate> result=new ArrayList<>();
        result.add(new Candidate("MC68332","CPU32","SIMCR",0x7ffa00));
        result.add(new Candidate("MC68332","CPU32","SIMCR",0xfffa00));
        if(scriptFile!=null){
            Path table=scriptFile.toPath().getParent().resolve("hardware_profiles.tsv");
            if(Files.isRegularFile(table)){
                int n=0;
                for(String line:Files.readAllLines(table,StandardCharsets.UTF_8)){
                    n++;
                    if(line.isBlank()||line.trim().startsWith("#"))continue;
                    String[] a=line.split("\t",-1);
                    if(a.length!=7)throw new IllegalArgumentException("Invalid TSV row "+n);
                    long addr=Long.decode(a[3]);
                    if(addr<0||addr>0xffffffL)throw new IllegalArgumentException("Invalid address TSV row "+n);
                    result.add(new Candidate(a[0],a[1],a[2],addr));
                }
            }
        }
        return result;
    }
    private static String hex(long l){return String.format(Locale.ROOT,"0x%06X",l);}
    private static String clean(String v){
        return v.replace("\r"," ").replace("\n"," ").replace("|","/").replace("\t"," ");
    }
    private static String csv(String s){
        return "\""+s.replace("\"","\"\"").replace("\r"," ").replace("\n"," ")+"\"";
    }
    private static String proposed(Candidate c){
        String map=c.address>=0x800000L?"MM1":"MM0";
        return ("HW_"+c.device+"_"+c.register+"_"+map)
            .replaceAll("[^a-zA-Z0-9_]","_");
    }
    @Override
    public void run()throws Exception{
        if(currentProgram==null){printerr("Open a Ghidra program first.");return;}
        String selected=askChoice("Hardware evidence export",
            "Choosing a profile only labels hypotheses; no processor is identified by this action.",
            List.of("CPU32","MC68332"),"CPU32");
        boolean family=selected.equals("CPU32");
        List<Candidate> all=catalog(getSourceFile());
        Map<Long,List<Candidate>> addresses=new LinkedHashMap<>();
        for(Candidate c:all){
            if(family?c.family.equals(selected):c.device.equals(selected)){
                List<Candidate> same=addresses.computeIfAbsent(c.address,k->new ArrayList<>());
                boolean present=false;
                for(Candidate prior:same)
                    if(prior.device.equals(c.device)&&prior.register.equals(c.register))present=true;
                if(!present)same.add(c);
            }
        }
        StringBuilder md=new StringBuilder();
        StringBuilder names=new StringBuilder("address,existing_name,proposed_name,profile,register,evidence_count,status\n");
        md.append("# Hardware register hypotheses — local Ghidra evidence\n\n")
          .append("- Program: `").append(clean(currentProgram.getName())).append("`\n")
          .append("- Ghidra ISA: `").append(currentProgram.getLanguageID()).append("`\n")
          .append("- User-selected reference: `").append(selected).append("`\n")
          .append("- CPU identification: **NOT PROVEN**; hardware matches are conditional\n")
          .append("- Source for MC68332 mapping: [MC68332 User Manual](https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf); match register and bit-field details against the original PDF\n")
          .append("- Critical: current MM state, CSPAR pin assignments, CSOR bus conditions, path execution and physical wiring are unresolved\n")
          .append("- u-Link NT: DO NOT treat any hypothesized window as a verified flash/RAM access region\n\n");
        md.append("## Candidate register references\n\n")
          .append("| Profile | Register | Address | Ghidra symbol | Code reference count |\n")
          .append("|---|---|---:|---|---:|\n");
        int hitRegisters=0,totalRefs=0,previewCount=0;
        Set<String> previewDuplicates=new LinkedHashSet<>();
        StringBuilder evidence=new StringBuilder("\n## Static instruction evidence\n\n");
        for(Map.Entry<Long,List<Candidate>> pair:addresses.entrySet()){
            monitor.checkCancelled();
            Address address=currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress(pair.getKey());
            Symbol primary=currentProgram.getSymbolTable().getPrimarySymbol(address);
            String existing=primary==null?"":primary.getName();
            ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(address);
            List<String> lines=new ArrayList<>();
            while(refs.hasNext()){
                monitor.checkCancelled();
                Reference r=refs.next();
                Instruction insn=currentProgram.getListing().getInstructionContaining(r.getFromAddress());
                if(insn==null)continue;
                Function function=currentProgram.getFunctionManager()
                    .getFunctionContaining(insn.getAddress());
                lines.add("- `"+insn.getAddress()+"` `"+clean(insn.toString())+
                    "` — "+(r.getReferenceType().isWrite()?"write reference":"read/other reference")+
                    "; Ghidra function `"+(function==null?"?":clean(function.getName()))+"`");
            }
            if(lines.isEmpty())continue;
            hitRegisters++;
            totalRefs+=lines.size();
            for(Candidate c:pair.getValue()){
                md.append("| ").append(clean(c.device)).append(" | ")
                  .append(clean(c.register)).append(" | `").append(hex(c.address))
                  .append("` | `").append(clean(existing)).append("` | ")
                  .append(lines.size()).append(" |\n");
                String proposal=proposed(c);
                boolean userName=!existing.isBlank()&&!existing.startsWith("DAT_")&&
                    !existing.startsWith("UNK_")&&!existing.startsWith("LAB_");
                String status=userName?"KEEP EXISTING NAME":"HYPOTHESIS, MANUAL REVIEW ONLY";
                String id=hex(c.address)+":"+proposal;
                if(previewDuplicates.add(id)){
                    names.append(csv(hex(c.address))).append(",")
                        .append(csv(existing)).append(",")
                        .append(csv(proposal)).append(",")
                        .append(csv(c.device)).append(",")
                        .append(csv(c.register)).append(",")
                        .append(lines.size()).append(",")
                        .append(csv(status)).append("\n");
                    if(!userName)previewCount++;
                }
            }
            evidence.append("### `").append(hex(pair.getKey())).append("` — ");
            for(Candidate c:pair.getValue()) evidence.append(c.device).append("/")
                .append(c.register).append(" ");
            evidence.append("\n\n");
            for(String l:lines)evidence.append(l).append("\n");
            evidence.append("\n");
        }
        md.append(evidence);
        md.append("## Analysis handoff\n\n")
          .append("Use this report as RAG context, not as evidence of processor identity. ")
          .append("Investigate entry/reset paths, MM write-once, function code and privilege spaces, ")
          .append("VBR, all CSBAR/CSOR/CSPAR values, TRAMBAR relocation and physical wiring. ")
          .append("Model each possible configuration epoch separately. ")
          .append("Names in the accompanying CSV are **proposals only**, never applied.\n");
        println("Hardware references in report: "+totalRefs+
            "; different referenced register addresses: "+hitRegisters+
            "; proposed name rows needing manual review: "+previewCount);
        File dest=askFile("Save hardware evidence Markdown (index this in GhidrAssist RAG)",
            "Save");
        if(dest==null){println("Export cancelled. No files or Ghidra database changed.");return;}
        Path markdown=dest.toPath();
        if(!markdown.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".md"))
            markdown=markdown.resolveSibling(markdown.getFileName()+".md");
        String filename=markdown.getFileName().toString();
        Path csvPath=markdown.resolveSibling(filename.substring(0,filename.length()-3)+"_name_preview.csv");
        if((Files.exists(markdown)||Files.exists(csvPath)) &&
                !askYesNo("Overwrite existing report?",
                    "The Markdown report or CSV already exists. Overwrite both?")){
            println("No export files changed.");return;
        }
        Files.writeString(markdown,md.toString(),StandardCharsets.UTF_8);
        Files.writeString(csvPath,names.toString(),StandardCharsets.UTF_8);
        println("RAG IMPORT FILE: "+markdown);
        println("NAMES REVIEW FILE: "+csvPath);
        println("The CSV does not rename symbols. No Ghidra program changes were made.");
    }
}
