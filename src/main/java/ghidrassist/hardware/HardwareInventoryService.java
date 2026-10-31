package ghidrassist.hardware;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Read-only, source-provenanced Ghidra evidence for hypothetical internal MCU
 * registers. The same MC68332 candidate address may be shared by other CPU32
 * devices. All generated windows are configuration *sketches* grouped by Ghidra
 * function; they do not imply that those functions execute or execute in order.
 */
public final class HardwareInventoryService {
    public static final class Site {
        public final Address pc;
        public final long registerAddress;
        public final String register;
        public final String function;
        public final String asm;
        public final boolean write;
        public final Integer literal;
        private Site(Address pc,long address,String register,String function,
                String asm,boolean write,Integer literal){
            this.pc=pc;
            this.registerAddress=address;
            this.register=register;
            this.function=function;
            this.asm=asm;
            this.write=write;
            this.literal=literal;
        }
    }
    public static final class Report {
        public final String program,language,selection;
        public final int uniqueSites,functions;
        public final List<Site> sites;
        public final String markdown;
        public final String overviewMarkdown;
        public final String detailsMarkdown;
        public final String namePreviewCsv;
        public final String configurationEvidenceCsv;
        public final HardwareCsbarUnifiedReview.Review csbarReview;
        public final List<HardwareFunctionNamingReview.Proposal> functionProposals;
        private Report(String program,String language,String selection,List<Site> sites,
                String overviewMarkdown,String detailsMarkdown,String namePreviewCsv,
                String configurationEvidenceCsv,int functions,
                List<HardwareFunctionNamingReview.Proposal> functionProposals,
                HardwareCsbarUnifiedReview.Review csbarReview){
            this.program=program;
            this.language=language;
            this.selection=selection;
            this.uniqueSites=(int)sites.stream().filter(site->
                HardwareReportScope.isInitializationRegister(site.register)).count();
            this.sites=List.copyOf(sites);
            this.overviewMarkdown=overviewMarkdown;
            this.detailsMarkdown=detailsMarkdown;
            this.markdown=overviewMarkdown+"\n\n---\n\n"+detailsMarkdown;
            this.namePreviewCsv=namePreviewCsv;
            this.configurationEvidenceCsv=configurationEvidenceCsv;
            this.functions=functions;
            this.functionProposals=List.copyOf(functionProposals);
            this.csbarReview=java.util.Objects.requireNonNull(csbarReview);
        }
    }

    private static String hex(long v,int n) {
        return ChipSelectModel.hex(v,n);
    }
    private static String mnemonic(Instruction insn){
        String name=insn.getMnemonicString().toUpperCase(Locale.ROOT);
        int dot=name.indexOf('.');
        return dot<0?name:name.substring(0,dot);
    }
    private static long referenceDestination(Instruction insn,int op){
        Object[] obj=insn.getOpObjects(op);
        if(obj==null)return -1;
        for(Object o:obj)if(o instanceof Address a)return a.getOffset();
        return -1;
    }
    private static Integer literalWord(Instruction i,long target) {
        if(i.getNumOperands()<1)return null;
        int last=i.getNumOperands()-1;
        String dest=i.getDefaultOperandRepresentation(last);
        if(dest==null || dest.contains("#") || referenceDestination(i,last)!=target)
            return null;
        if(!i.getMnemonicString().toUpperCase(Locale.ROOT).endsWith(".W"))
            return null;
        if(i.getNumOperands()==1 && mnemonic(i).equals("CLR"))
            return 0;
        if(i.getNumOperands()==2 && mnemonic(i).equals("MOVE")){
            String source=i.getDefaultOperandRepresentation(0);
            Scalar s=i.getScalar(0);
            if(source!=null && source.trim().startsWith("#") && s!=null)
                return (int)(s.getUnsignedValue()&0xffff);
        }
        return null;
    }
    private static boolean knownWrite(Instruction i,long target){
        int last=i.getNumOperands()-1;
        if(last<0||referenceDestination(i,last)!=target)return false;
        return switch(mnemonic(i)){
            case "MOVE","MOVEA","CLR","ORI","ANDI","EORI",
                 "BSET","BCLR","ADD","ADDI","SUB","SUBI" -> true;
            default -> false;
        };
    }
    public Report scan(Program program,boolean concreteDevice,TaskMonitor monitor)
            throws CancelledException {
        if(program==null)throw new IllegalArgumentException("A loaded Ghidra program is required");
        return scan(program,concreteDevice,monitor,HardwareAnalysisRevision.capture(
            program,program.getModificationNumber(),
            program.getLanguageID().toString(),program.getExecutableSHA256(),
            concreteDevice));
    }

    public Report scan(Program program,boolean concreteDevice,TaskMonitor monitor,
            HardwareAnalysisRevision revision) throws CancelledException {
        if(program==null)throw new IllegalArgumentException("A loaded Ghidra program is required");
        if(monitor==null)monitor=TaskMonitor.DUMMY;
        monitor.checkCancelled();
        // A complete CFG stage is saved BEFORE the reference-inventory stage.
        // If the user cancels the later stage, a same-revision retry can
        // reuse this exact conservative CFG evidence without recalculating it.
        HardwareFlowStageCache.Result flowStage=
            HardwareFlowStageCache.loadOrAnalyze(program,revision,monitor);
        monitor.checkCancelled();
        HardwareProfiles.Profile profile=HardwareProfiles.mc68332();
        Map<Long,HardwareProfiles.Register> byAddress=new LinkedHashMap<>();
        for(HardwareProfiles.Register r:profile.registers)
            for(int mm=0;mm<2;mm++)
                byAddress.put(profile.absoluteAddress(r,mm),r);
        Map<String,Site> found=new LinkedHashMap<>();
        for(Map.Entry<Long,HardwareProfiles.Register> record:byAddress.entrySet()){
            monitor.checkCancelled();
            Address dest=program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(record.getKey());
            ReferenceIterator refs=program.getReferenceManager().getReferencesTo(dest);
            while(refs.hasNext()){
                monitor.checkCancelled();
                Reference ref=refs.next();
                Instruction i=program.getListing().getInstructionContaining(ref.getFromAddress());
                if(i==null)continue;
                Function f=program.getFunctionManager().getFunctionContaining(i.getAddress());
                String fn=f==null?"<unrecognized>":f.getName()+" @ "+f.getEntryPoint();
                boolean write=knownWrite(i,record.getKey());
                String key=i.getAddress()+"/"+record.getKey();
                Site current=new Site(i.getAddress(),record.getKey(),record.getValue().name,
                    fn,i.toString(),write,write?literalWord(i,record.getKey()):null);
                found.putIfAbsent(key,current);
            }
        }
        // For raw binary programs whose references have not been initialized:
        // supplement only direct absolute destination forms, not generic
        // constants that might accidentally equal internal-module addresses.
        InstructionIterator iterator=program.getListing().getInstructions(true);
        int scanned=0;
        StringBuilder vbrEvidence=new StringBuilder();
        int vbrCount=0;
        while(iterator.hasNext()){
            monitor.checkCancelled();
            Instruction i=iterator.next();scanned++;
            if(mnemonic(i).equals("MOVEC") &&
                    i.toString().toUpperCase(Locale.ROOT).contains("VBR")){
                Function f=program.getFunctionManager().getFunctionContaining(i.getAddress());
                vbrEvidence.append("- `").append(i.getAddress()).append("` `")
                    .append(i).append("` — ")
                    .append(f==null?"<unrecognized>":f.getName())
                    .append("; control register operation, VBR base UNKNOWN without flow analysis\n");
                vbrCount++;
            }
            int last=i.getNumOperands()-1;
            if(last<0)continue;
            long addr=referenceDestination(i,last);
            HardwareProfiles.Register reg=byAddress.get(addr);
            if(reg==null || !knownWrite(i,addr))continue;
            String key=i.getAddress()+"/"+addr;
            if(found.containsKey(key))continue;
            Function f=program.getFunctionManager().getFunctionContaining(i.getAddress());
            String fn=f==null?"<unrecognized>":f.getName()+" @ "+f.getEntryPoint();
            found.put(key,new Site(i.getAddress(),addr,reg.name,fn,i.toString(),true,
                literalWord(i,addr)));
        }
        List<Site> sites=new ArrayList<>(found.values());
        sites.sort(Comparator.comparing((Site s)->s.function)
            .thenComparing(s->s.pc).thenComparingLong(s->s.registerAddress));
        Map<String,List<Site>> grouped=new LinkedHashMap<>();
        // Keep the full register set for CS pin-state inference; display below
        // only the focused initialization sites and their parent functions.
        for(Site site:sites)
            grouped.computeIfAbsent(site.function,k->new ArrayList<>()).add(site);
        String choice=concreteDevice?"MC68332 (MANUALLY ASSUMED)":"CPU32 (MC68332-ADDRESS RECONNAISSANCE)";
        StringBuilder md=new StringBuilder();
        md.append("# Hardware Evidence — read-only\n\n")
          .append("- Program: `").append(program.getName()).append("`\n")
          .append("- Ghidra language: `").append(program.getLanguageID()).append("`\n")
          .append("- Selection: **").append(choice).append("**\n")
          .append("- Scanned Listing instructions: ").append(scanned).append("\n")
          .append("- Initialization-register reference sites shown: ")
            .append(sites.stream().filter(s->HardwareReportScope.isInitializationRegister(s.register)).count())
            .append("\n")
          .append("- Other MCU register references: ")
            .append(sites.stream().filter(s->!HardwareReportScope.isInitializationRegister(s.register)).count())
            .append(" (retained internally; definitions available in Review / Apply)\n")
          .append("- Firmware origin: currently loaded Ghidra project, NOT a device readback\n")
          .append("- MCU identity, active MM map, reached branches, connected chips and memory wiring: **NOT VERIFIED**\n")
          .append("- Register address provenance: [MC68332 User's Manual](https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf)\n\n");
        md.append(HardwareProfileAudit.inspect(concreteDevice ?
            profile : HardwareProfiles.cpu32Family()).markdown());
        md.append("## Initialization/memory-map evidence (SIMCR/MM, TRAMBAR, CSBAR, CSOR, VBR)\n\n")
          .append("CSPAR contributes to conditional chip-select decoding but is not listed as a separate register site.\n\nMC68332 sourced bitfields are shown only for exact full-word literal SIMCR MOVEs; they are static candidate values, not proven execution or latched MM state.\n\n");
        for(Map.Entry<String,List<Site>> group:grouped.entrySet()){
            monitor.checkCancelled();
            if(group.getValue().stream().noneMatch(site->
                    HardwareReportScope.isInitializationRegister(site.register)))
                continue;
            md.append("### ").append(group.getKey()).append("\n\n");
            // Different MM windows never form one combined state.
            for(int mm=0;mm<=1;mm++){
                List<HardwareStaticWordConsensus.Observation> localWrites=
                    new ArrayList<>();
                for(Site site:group.getValue())
                    if((site.registerAddress<0x800000L?0:1)==mm)
                        localWrites.add(new HardwareStaticWordConsensus.Observation(
                            site.register,site.write,site.literal));
                var consensus=HardwareStaticWordConsensus.inspect(localWrites);
                // No source-PC last-write-wins: any conflicting or unknown
                // write excludes the register from a single-value sketch.
                Map<String,Integer> values=consensus.singleLiteralCandidates();
                boolean any=false;
                for(Site site:group.getValue()){
                    if((site.registerAddress<0x800000L?0:1)!=mm)continue;
                    // CSPAR and other register writes update internal context,
                    // but only key initialization registers appear as rows.
                    if(!HardwareReportScope.isInitializationRegister(site.register))
                        continue;
                    any=true;
                    md.append("- `").append(site.pc).append("` ")
                      .append(site.register).append(" `")
                      .append(hex(site.registerAddress,6)).append("` — ")
                      .append(site.write?"WRITE":"READ/REFERENCE")
                      .append("; ").append(site.literal==null?"value UNKNOWN":hex(site.literal,4))
                      .append("; `").append(site.asm).append("`");
                    // Only a literal full-width word MOVE supports exact SIMCR
                    // bit decoding. Byte/indirect/derived writes remain UNKNOWN.
                    if (concreteDevice && site.write && site.literal != null &&
                            "SIMCR".equals(site.register) &&
                            site.asm.stripLeading().toUpperCase(Locale.ROOT)
                                .matches("MOVE\\.W\\s+#.*")) {
                        md.append("; ")
                          .append(HardwareBitfieldDecoder.decode(
                              profile,"SIMCR",site.literal,16).summary());
                    }
                    md.append("\n");
                }
                if(!any)continue;
                md.append("\n**MM=").append(mm)
                    .append(" conditional candidate snapshot (NOT active state)**\n\n");
                md.append("- ").append(consensus.description()).append(". ")
                    .append("Alternative/unknown sites are excluded from any ")
                    .append("single-value CS table.\n\n");
                if(concreteDevice && !values.isEmpty()){
                    md.append("**Per-select Chip Select table (conditional; function-local code sites)**\n\n");
                    md.append(ChipSelectTable.markdown(values, true));
                } else if(!concreteDevice) {
                    md.append(ChipSelectTable.markdown(values, false));
                }
                md.append("\n");
            }
        }
        md.append("## VBR control register evidence (not memory-mapped SIM)\n\n")
          .append("- Candidate MOVEC VBR instructions: ").append(vbrCount).append("\n")
          .append(vbrEvidence).append("\n");
        md.append("## Important limitations\n\n")
          .append("1. Site order is address order, **not a proven execution trace**. Last-write-wins cannot be assumed across branches/calls.\n")
          .append("2. No constant propagation across register pointers, indirect writes, loops or interprocedural paths. Unknown writes invalidate values.\n")
          .append("3. CSBAR gives only a *potential* window. CSOR, CSPAR, MM, CPU function codes, exception/boot state, bus wiring and external device presence remain separate requirements.\n")
          .append("4. VBR is a CPU control register; read separate VBR analysis. A register address match is not proof of a particular physical MCU.\n")
          .append("5. This report is usable as RAG context with uncertainty preserved; do not automatically rename functions, set memory blocks or program any u-Link NT address from it.\n");
        Map<Long,String> registerNames=new LinkedHashMap<>();
        Map<Long,String> existingLabels=new LinkedHashMap<>();
        Map<Long,Integer> evidenceCounts=new LinkedHashMap<>();
        for(Site site:sites) {
            registerNames.putIfAbsent(site.registerAddress,site.register);
            evidenceCounts.merge(site.registerAddress,1,Integer::sum);
        }
        for(long address:registerNames.keySet()) {
            monitor.checkCancelled();
            Address pointer=program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(address);
            Symbol existing=program.getSymbolTable().getPrimarySymbol(pointer);
            existingLabels.put(address,existing==null?"":existing.getName());
        }
        Set<String> reserved=new HashSet<>();
        // Global collision detection: a candidate label must not already
        // exist elsewhere in the program's symbol table.
        SymbolIterator symbols=program.getSymbolTable().getAllSymbols(true);
        while(symbols.hasNext()){
            monitor.checkCancelled();
            Symbol sym=symbols.next();
            if(sym!=null && sym.getName()!=null)reserved.add(sym.getName());
        }
        String csv=HardwareNamingReview.toCsv(
            HardwareNamingReview.propose(concreteDevice,"MC68332",
                registerNames,existingLabels,evidenceCounts,reserved));
        // Function roles require separate, direct WRITE evidence across
        // multiple distinct register names. Existing user names are preserved.
        // Proposals share the seven-column register CSV and remain review-only.
        List<HardwareFunctionNamingReview.Observation> functionWrites=new ArrayList<>();
        for(Site site:sites) {
            if(!site.write)continue;
            Function function=program.getFunctionManager().getFunctionContaining(site.pc);
            if(function==null)continue;
            functionWrites.add(new HardwareFunctionNamingReview.Observation(
                function.getEntryPoint().getOffset(),function.getName(),
                site.pc.getOffset(),site.register,true));
        }
        List<HardwareFunctionNamingReview.Proposal> functionProposals =
            HardwareFunctionNamingReview.propose(concreteDevice,functionWrites,reserved);
        csv+=HardwareFunctionNamingReview.toCsvRows(functionProposals);
        md.append("\n## Naming review\n\n")
          .append("Naming is preview-only, exported as separate CSV. ")
          .append("Generic CPU32 mode deliberately emits no device-specific proposed names. ")
          .append("A manually selected MCU is still unverified: review before any future application.\n")
          .append("Candidate function roles: ").append(functionProposals.size())
          .append(" (direct multi-register write evidence only; no renaming performed).\n")
          .append("Function rows in the same CSV have register column FUNCTION_ROLE; ")
          .append("unknown/indirect-only roles and runtime reachability remain unresolved.\n");
        // The completed CFG stage came from the matching program revision;
        // never treat this as a successful partial CFG resume.
        md.append("\n\n- CFG/P-code completed-stage checkpoint: ")
            .append(flowStage.reused()?"REUSED same revision":"COMPUTED for this revision")
            .append("; no cross-session resume or runtime execution asserted.\n\n")
            .append(flowStage.report().markdown);
        int initializationFunctions=(int)grouped.values().stream().filter(group->
            group.stream().anyMatch(site->
                HardwareReportScope.isInitializationRegister(site.register))).count();
        List<HardwareReportOverview.Site> overviewSites=new ArrayList<>();
        for(Site site:sites)
            overviewSites.add(new HardwareReportOverview.Site(
                site.register,site.write,site.literal!=null));
        String overview=HardwareReportOverview.render(concreteDevice,scanned,
            initializationFunctions,vbrCount,flowStage.report().unresolved,
            flowStage.report().limited,overviewSites);
        csv+=HardwarePointerRoleReview.csvRows(flowStage.report().pointerRoles);
        // One source PC can be observed in both Listing/XREF and CFG/P-code.
        // The reconciler counts it only once and refuses to combine
        // contradictory widths/words into a confident literal.
        List<HardwareStartupEvidenceMerge.Observation> sources=new ArrayList<>();
        for(Site site:sites){
            monitor.checkCancelled();
            Function f=program.getFunctionManager().getFunctionContaining(site.pc);
            if(f==null)continue; // UNKNOWN owning function: do not invent call ancestry
            Instruction instruction=program.getListing().getInstructionAt(site.pc);
            String mnemonic=instruction==null?"":instruction.getMnemonicString()
                .toUpperCase(Locale.ROOT);
            int width=mnemonic.endsWith(".W")?16:
                mnemonic.endsWith(".B")?8:mnemonic.endsWith(".L")?32:0;
            sources.add(new HardwareStartupEvidenceMerge.Observation(
                f.getEntryPoint().getOffset(),site.pc.getOffset(),
                site.registerAddress,site.register,
                HardwareStartupEvidenceMerge.Source.LISTING_REFERENCE,
                site.write,width,site.literal,false));
        }
        for(HardwareCfgWriteAudit.Site s:flowStage.report().rawCfgMmioSites){
            monitor.checkCancelled();
            sources.add(new HardwareStartupEvidenceMerge.Observation(
                s.function(),s.pc(),s.address(),s.register(),
                HardwareStartupEvidenceMerge.Source.CFG_PCODE,
                true,s.widthBits(),s.literal(),
                s.unknownCall() || s.unknownStore() || s.functionIncomplete()));
        }
        var merged=HardwareStartupEvidenceMerge.reconcile(sources);
        md.append("\n\n").append(merged.markdown(concreteDevice));
        overview=HardwareReportOverview.withUnifiedSources(overview,merged);
        List<HardwareStartupConfig.Site> startupSites=new ArrayList<>();
        for(var item:merged.rows())
            startupSites.add(item.forStartup(
                merged.functionsWithUnknownAlias().contains(item.function())));
        var startup=HardwareStartupConfig.analyze(concreteDevice,
            flowStage.report().resetCandidateRecognized,
            flowStage.report().resetCandidateFunctions,
            flowStage.report().resetGraphIncomplete,startupSites);
        md.append("\n\n").append(startup.markdown());
        var guardedCsbar=HardwareCsbarUnifiedReview.inspect(concreteDevice,merged,
            flowStage.report().cfgReviewComplete);
        md.append("\n\n## Review / Apply source-safety gate\n\n- ")
            .append(guardedCsbar.summary()).append("\n");
        return new Report(program.getName(),program.getLanguageID().toString(),choice,sites,
            overview,md.toString(),csv,
            HardwareConfigurationEvidenceCsv.withUnifiedSources(
                flowStage.report().configurationEvidenceCsv,merged,concreteDevice),
            initializationFunctions,functionProposals,guardedCsbar);
    }
}
