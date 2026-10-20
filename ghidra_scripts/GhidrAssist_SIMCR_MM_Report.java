// Standalone read-only reconnaissance for Ghidra 12.1.4.
// Copy this Java file into any Ghidra Script Manager directory.
// Optionally add hardware_profiles.tsv beside it to extend MCU profiles.
//@category GhidrAssist.Hardware

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Read-only CPU-family reconnaissance / concrete-MCU candidate register probe.
 * Does not depend on GhidrAssist extension classes and never modifies the Ghidra project.
 *
 * Built-in entries come from the MC68332 register map. To expand supported devices,
 * copy an optional hardware_profiles.tsv beside this script; see docs/hardware-analysis.md.
 * Address matches alone DO NOT identify the processor or prove runtime accesses.
 */
public class GhidrAssist_SIMCR_MM_Report extends GhidraScript {
    private static final String[] BUILTIN = {
        "MC68332\tCPU32\tSIMCR\t0x7FFA00\t16\t0x0040\tSIMCR_MM",
        "MC68332\tCPU32\tSIMCR\t0xFFFA00\t16\t0x0040\tSIMCR_MM"
    };

    private static final class Target {
        final String device, family, register, role;
        final long address;
        final int width, mask;

        Target(String device, String family, String register, long address,
                int width, int mask, String role) {
            this.device = device;
            this.family = family;
            this.register = register;
            this.address = address;
            this.width = width;
            this.mask = mask;
            this.role = role;
        }

        String identity() {
            return device + "/" + register + "/0x" + Long.toHexString(address);
        }

        String key() {
            return device + "\t" + register + "\t" + address;
        }
    }

    private static final class Site {
        final Instruction instruction;
        final long destination;
        boolean write;
        String evidence;
        Site(Instruction instruction, long destination, boolean write, String evidence) {
            this.instruction = instruction;
            this.destination = destination;
            this.write = write;
            this.evidence = evidence;
        }
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            printerr("Open a Ghidra program first.");
            return;
        }
        List<Target> catalog = loadCatalog();
        Set<String> families = new LinkedHashSet<>();
        Set<String> devices = new LinkedHashSet<>();
        for (Target target : catalog) {
            families.add(target.family);
            devices.add(target.device);
        }
        List<String> choices = new ArrayList<>(families);
        List<String> sortedDevices = new ArrayList<>(devices);
        Collections.sort(sortedDevices);
        choices.addAll(sortedDevices);
        if (choices.isEmpty()) {
            printerr("No usable hardware profiles are installed.");
            return;
        }

        String preferred = families.contains("CPU32") ? "CPU32" : choices.get(0);
        String choice = askChoice("Hardware profile or CPU family",
            "Family = reconnaissance only; device = candidate register decoding. " +
                "An ISA language ID does not identify a chip.",
            choices, preferred);
        boolean familyMode = families.contains(choice);
        List<Target> selected = new ArrayList<>();
        for (Target target : catalog) {
            if ((familyMode && choice.equals(target.family)) ||
                    (!familyMode && choice.equals(target.device))) {
                selected.add(target);
            }
        }
        Map<Long, List<Target>> addresses = new TreeMap<>();
        for (Target target : selected) {
            addresses.computeIfAbsent(target.address, k -> new ArrayList<>()).add(target);
            if ("SIMCR_MM".equals(target.role) && target.width == 16) {
                addresses.computeIfAbsent(target.address + 1, k -> new ArrayList<>()).add(target);
            }
        }
        println("Program: " + currentProgram.getName());
        println("Ghidra language (not hardware proof): " + currentProgram.getLanguageID());
        println("Mode: " + (familyMode ? "FAMILY RECONNAISSANCE" : "CONCRETE DEVICE PROFILE (user-selected)"));
        println("Selection: " + choice + " ; candidate hardware addresses: " + addresses.size());
        if (familyMode) {
            println("Candidate devices in catalog: " + String.join(", ", devicesIn(selected)));
            println("Any reported register name is a HYPOTHESIS tied to a candidate profile.");
        }
        println("READ ONLY. No names, memory blocks, bytes or properties will be changed.");
        println();

        Map<String, Site> findings = new LinkedHashMap<>();
        int xrefs = 0;
        for (long numeric : addresses.keySet()) {
            monitor.checkCancelled();
            Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(numeric);
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(addr);
            while (refs.hasNext()) {
                monitor.checkCancelled();
                Reference ref = refs.next();
                xrefs++;
                Instruction insn = currentProgram.getListing().getInstructionContaining(ref.getFromAddress());
                if (insn != null) add(findings, insn, numeric,
                    ref.getReferenceType().isWrite(), "XREF");
            }
        }
        int scanned = 0;
        InstructionIterator iter = currentProgram.getListing().getInstructions(true);
        while (iter.hasNext()) {
            monitor.checkCancelled();
            Instruction insn = iter.next();
            scanned++;
            String mnemonic = baseMnemonic(insn);
            if (!(mnemonic.startsWith("MOVE") || mnemonic.equals("ORI") ||
                    mnemonic.equals("ANDI") || mnemonic.equals("EORI") ||
                    mnemonic.equals("BSET") || mnemonic.equals("BCLR"))) continue;
            int op = insn.getNumOperands() - 1;
            if (op < 1 || !isAbsoluteDestination(insn, op)) continue;
            Object[] operands = insn.getOpObjects(op);
            if (operands == null) continue;
            for (Object object : operands) {
                long candidate = -1;
                if (object instanceof Address a) candidate = a.getOffset();
                else if (object instanceof Scalar s) candidate = s.getUnsignedValue();
                if (addresses.containsKey(candidate)) {
                    add(findings, insn, candidate, true, "absolute destination");
                }
            }
        }

        List<Site> sites = new ArrayList<>(findings.values());
        sites.sort(Comparator.comparing((Site s) -> s.instruction.getAddress())
                .thenComparingLong(s -> s.destination));
        println("Scanned instructions: " + scanned + "; XREF hits: " + xrefs +
            "; unique candidate instruction/address sites: " + sites.size());
        if (sites.isEmpty()) println("No candidate sites found in current disassembly.");
        for (Site site : sites) {
            monitor.checkCancelled();
            Function function = currentProgram.getFunctionManager().getFunctionContaining(site.instruction.getAddress());
            String functionName = function == null ? "<no recognized function>" :
                function.getName() + " @ " + function.getEntryPoint();
            println(site.instruction.getAddress() + "  " + site.instruction +
                " [" + site.evidence + (site.write ? "; write candidate]" : "; reference only]"));
            println("    In function: " + functionName);
            println("    Matched address: 0x" + Long.toHexString(site.destination).toUpperCase(Locale.ROOT));
            Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(
                currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(site.destination));
            println("    Existing Ghidra symbol: " + (symbol == null ? "<none>" : symbol.getName()));
            for (Target target : addresses.get(site.destination)) {
                println("    CANDIDATE " + target.identity() + " (" + target.family + ") : " +
                    interpret(site, target));
            }
        }
        println();
        println("LIMITS: Matching an address is not proof of processor identity, " +
            "actual device selection, execution, or a memory map. Static sites can " +
            "be unreachable; register-indirect accesses may be missed.");
        println("SIMCR/MM on MC68332 is write-once after reset; repeated candidate " +
            "stores are not repeated successful relocations. " +
            "Interpreting 0xFFFA00 as SIMCR requires the corresponding active MM map.");
        println("NEXT: check containing functions, entry/reset path, indirect writes, " +
            "then CSPAR/CSBAR/CSOR and all dynamic address spaces.");
    }

    private static List<String> devicesIn(List<Target> targets) {
        Set<String> result = new LinkedHashSet<>();
        for (Target t : targets) result.add(t.device);
        return new ArrayList<>(result);
    }

    private void add(Map<String, Site> found, Instruction insn, long addr,
            boolean write, String evidence) {
        String key = insn.getAddress() + "/" + Long.toHexString(addr);
        Site existing = found.get(key);
        if (existing == null) {
            found.put(key, new Site(insn, addr, write, evidence));
        }
        else if (write && !existing.write) {
            existing.write = true;
            existing.evidence = evidence;
        }
    }

    private static String baseMnemonic(Instruction insn) {
        String m = insn.getMnemonicString().toUpperCase(Locale.ROOT);
        int dot = m.indexOf('.');
        return dot < 0 ? m : m.substring(0, dot);
    }

    private static boolean isAbsoluteDestination(Instruction insn, int op) {
        Object[] objects = insn.getOpObjects(op);
        if (objects == null) return false;
        for (Object o : objects) if (o instanceof Register) return false;
        String text = insn.getDefaultOperandRepresentation(op);
        if (text == null || text.isBlank() || text.contains("#") ||
                text.contains("[") || text.contains("%")) return false;
        return !text.toUpperCase(Locale.ROOT).matches(
            ".*(?<![A-Z0-9])(?:A[0-7]|D[0-7]|PC|SP)(?![A-Z0-9]).*");
    }

    private static String interpret(Site site, Target target) {
        if (!site.write) return "UNRESOLVED (XREF not marked as a write)";
        Instruction insn = site.instruction;
        int last = insn.getNumOperands() - 1;
        if (last != 1 || !isAbsoluteDestination(insn, 1)) {
            return "UNRESOLVED (indirect/non-binary operand)";
        }
        long observed = -1;
        for (Object o : insn.getOpObjects(1)) {
            if (o instanceof Address a) observed = a.getOffset();
            else if (o instanceof Scalar s) observed = s.getUnsignedValue();
        }
        if (observed != site.destination) return "UNRESOLVED (address not proven as destination)";
        String immediateText = insn.getDefaultOperandRepresentation(0);
        Scalar scalar = insn.getScalar(0);
        if (immediateText == null || !immediateText.trim().startsWith("#") || scalar == null) {
            return "UNRESOLVED (requires constant propagation or P-code)";
        }
        if (!"SIMCR_MM".equals(target.role)) {
            return "IMMEDIATE OPERATION, register-specific bit interpretation not implemented";
        }
        long value = scalar.getUnsignedValue();
        boolean lowByte = site.destination == target.address + 1;
        String mn = insn.getMnemonicString().toUpperCase(Locale.ROOT);
        boolean fullWord = !lowByte && mn.endsWith(".W");
        boolean byteLow = lowByte && mn.endsWith(".B");
        int mask = lowByte ? target.mask & 0xff : target.mask;
        String op = baseMnemonic(insn);
        boolean memoryBitOp = (op.equals("BSET") || op.equals("BCLR")) && lowByte;
        // BSET/BCLR memory destinations are byte operations on 68k even when
        // the printed mnemonic has no ".B" suffix.
        if (mask == 0 || !(fullWord || byteLow || memoryBitOp)) {
            return "UNRESOLVED (access width incompatible with defined MM field)";
        }
        boolean bit = (value & mask) != 0;
        String effect = "UNKNOWN";
        if (op.equals("MOVE")) effect = bit ? "SET_MM" : "CLEAR_MM";
        else if (op.equals("ORI")) effect = bit ? "SET_MM" : "PRESERVE_MM";
        else if (op.equals("ANDI")) effect = bit ? "PRESERVE_MM" : "CLEAR_MM";
        else if (op.equals("EORI")) effect = bit ? "TOGGLE_MM_REQUIRES_PREVIOUS_STATE" : "PRESERVE_MM";
        else if (memoryBitOp) {
            int bitNumber = Integer.numberOfTrailingZeros(mask);
            effect = value == bitNumber ? (op.equals("BSET") ? "SET_MM" : "CLEAR_MM") :
                "PRESERVE_MM";
        }
        return effect + " IF " + target.device + " profile and relevant SIMCR mapping apply";
    }

    private List<Target> loadCatalog() throws Exception {
        Map<String, Target> records = new LinkedHashMap<>();
        for (String row : BUILTIN) {
            Target target = parseRow(row, "built-in profile");
            records.put(target.key(), target);
        }
        if (getSourceFile() != null) {
            Path dir = Paths.get(getSourceFile().getAbsolutePath()).getParent();
            if (dir != null) {
                Path path = dir.resolve("hardware_profiles.tsv");
                if (Files.isRegularFile(path)) {
                    int lineNo = 0, added = 0;
                    for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                        lineNo++;
                        String trimmed = line.trim();
                        if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
                        Target item = parseRow(line, path + ":" + lineNo);
                        Target prior = records.putIfAbsent(item.key(), item);
                        if (prior == null) added++;
                        else if (prior.width != item.width || prior.mask != item.mask ||
                                 !prior.family.equals(item.family) ||
                                 !prior.role.equals(item.role)) {
                            throw new IllegalArgumentException("Conflicting profile entry at " +
                                path + ":" + lineNo + " : " + item.key());
                        }
                    }
                    println("Additional hardware catalog: " + path + " ; new entries: " + added);
                }
            }
        }
        return new ArrayList<>(records.values());
    }

    private static Target parseRow(String line, String source) {
        String[] fields = line.split("\t", -1);
        if (fields.length != 7) {
            throw new IllegalArgumentException("Bad hardware catalog row (expected 7 TAB fields): " + source);
        }
        String device = fields[0].trim(), family = fields[1].trim(),
            register = fields[2].trim(), role = fields[6].trim();
        if (device.isEmpty() || family.isEmpty() || register.isEmpty() ||
                !("SIMCR_MM".equals(role) || "OTHER".equals(role))) {
            throw new IllegalArgumentException("Missing or invalid catalog field: " + source);
        }
        long addr = Long.decode(fields[3].trim());
        int width = Integer.parseInt(fields[4].trim());
        int mask = Integer.decode(fields[5].trim());
        if (addr < 0 || addr > 0xffffffL || (width != 8 && width != 16 && width != 32) ||
                mask < 0 || (width < 32 && ((long) mask >>> width) != 0)) {
            throw new IllegalArgumentException("Address, width or mask out of range: " + source);
        }
        if ("SIMCR_MM".equals(role) && (width != 16 || Integer.bitCount(mask) != 1 || (mask & 0xff) == 0)) {
            throw new IllegalArgumentException("SIMCR_MM needs a 16-bit register and one low-byte MM bit: " + source);
        }
        return new Target(device, family, register, addr, width, mask, role);
    }
}
