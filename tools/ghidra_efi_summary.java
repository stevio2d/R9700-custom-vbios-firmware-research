// Static inventory helper for a decompressed EFI PE image.
// Run with Ghidra's analyzeHeadless -postScript option. It never runs the image.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

public class ghidra_efi_summary extends GhidraScript {
    private static String json(String value) {
        StringBuilder result = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\': result.append("\\\\"); break;
                case '"': result.append("\\\""); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        result.append(String.format("\\u%04x", (int)c));
                    } else {
                        result.append(c);
                    }
            }
        }
        return result.append('"').toString();
    }

    private String functionName(Address address) {
        Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
        return function == null ? null : function.getName();
    }

    private String functionEntry(Address address) {
        Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
        return function == null ? null : function.getEntryPoint().toString();
    }

    private String referenceJson(Reference reference) {
        Address target = reference.getToAddress();
        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(target);
        MemoryBlock block = currentProgram.getMemory().getBlock(target);
        StringBuilder item = new StringBuilder("{");
        item.append("\"target\":").append(json(target.toString()));
        item.append(",\"address_space\":").append(json(target.getAddressSpace().getName()));
        item.append(",\"reference_type\":").append(json(reference.getReferenceType().getName()));
        item.append(",\"operand_index\":").append(reference.getOperandIndex());
        item.append(",\"symbol\":").append(symbol == null ? "null" : json(symbol.getName()));
        item.append(",\"memory_block\":").append(block == null ? "null" : json(block.getName()));
        return item.append('}').toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 5) {
            throw new IllegalArgumentException(
                "Usage: ghidra_efi_summary.java <output.json> <entry-rva> <input-sha256> <ghidra-version> <archive-sha256>"
            );
        }
        File output = new File(args[0]);
        Address entryAddress = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(args[1]);
        Function entryFunction = currentProgram.getFunctionManager().getFunctionAt(entryAddress);

        int functionCount = 0;
        int directCallSiteTotal = 0;
        int namedFunctionCount = 0;
        List<String> namedFunctions = new ArrayList<>();
        List<String> sampleFunctions = new ArrayList<>();
        List<String> functionInventory = new ArrayList<>();
        List<String> directCallEdges = new ArrayList<>();
        List<String> indirectCallSites = new ArrayList<>();
        List<String> interruptSites = new ArrayList<>();
        List<String> functionCrossReferences = new ArrayList<>();
        Map<String, Set<String>> directCallGraph = new LinkedHashMap<>();
        Map<String, String> functionNamesByEntry = new LinkedHashMap<>();
        Map<String, List<String>> globalsByFunction = new LinkedHashMap<>();

        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            functionCount++;
            String entry = function.getEntryPoint().toString();
            functionNamesByEntry.put(entry, function.getName());
            directCallGraph.put(entry, new LinkedHashSet<String>());
            List<String> callSites = new ArrayList<>();
            List<String> indirectSitesForFunction = new ArrayList<>();
            List<String> dataReferences = new ArrayList<>();
            List<String> globalDataReferences = new ArrayList<>();
            List<String> bodyRanges = new ArrayList<>();
            int directCallSiteCount = 0;

            AddressRangeIterator bodyRangeIterator = function.getBody().getAddressRanges();
            while (bodyRangeIterator.hasNext()) {
                AddressRange range = bodyRangeIterator.next();
                bodyRanges.add("{\"start\":" + json(range.getMinAddress().toString()) +
                    ",\"end_inclusive\":" + json(range.getMaxAddress().toString()) +
                    ",\"start_offset_hex\":" + json("0x" + Long.toHexString(range.getMinAddress().getOffset())) +
                    ",\"end_offset_inclusive_hex\":" + json("0x" + Long.toHexString(range.getMaxAddress().getOffset())) +
                    ",\"length\":" + range.getLength() + "}");
            }

            if (!function.getName().startsWith("FUN_")) {
                namedFunctionCount++;
                if (namedFunctions.size() < 256) {
                    namedFunctions.add("{\"name\":" + json(function.getName()) +
                        ",\"entry\":" + json(entry) +
                        ",\"body_bytes\":" + function.getBody().getNumAddresses() +
                        ",\"body_address_count\":" + function.getBody().getNumAddresses() + "}");
                }
            }
            if (sampleFunctions.size() < 20) {
                sampleFunctions.add("{\"name\":" + json(function.getName()) +
                    ",\"entry\":" + json(entry) +
                    ",\"body_bytes\":" + function.getBody().getNumAddresses() +
                    ",\"body_address_count\":" + function.getBody().getNumAddresses() + "}");
            }

            InstructionIterator bodyInstructions = currentProgram.getListing().getInstructions(function.getBody(), true);
            while (bodyInstructions.hasNext()) {
                Instruction instruction = bodyInstructions.next();
                Address site = instruction.getAddress();
                List<String> siteDataReferences = new ArrayList<>();
                for (Reference reference : currentProgram.getReferenceManager().getReferencesFrom(site)) {
                    if (reference.getReferenceType().isData()) {
                        String item = referenceJson(reference);
                        siteDataReferences.add(item);
                        dataReferences.add(item);
                        if (currentProgram.getMemory().getBlock(reference.getToAddress()) != null) {
                            globalDataReferences.add(item);
                        }
                    }
                }

                if (!instruction.getFlowType().isCall()) {
                    continue;
                }
                if (instruction.getMnemonicString().equalsIgnoreCase("INT")) {
                    interruptSites.add("{\"caller_entry\":" + json(entry) +
                        ",\"caller_name\":" + json(function.getName()) +
                        ",\"site\":" + json(site.toString()) +
                        ",\"instruction\":" + json(instruction.toString()) +
                        ",\"interpretation\":\"Software interrupt instruction; vector behavior depends on the runtime environment and was not executed.\"}");
                    continue;
                }
                Address[] flows = instruction.getFlows();
                boolean computed = instruction.getFlowType().isComputed() || flows.length == 0;
                if (!computed) {
                    directCallSiteCount++;
                    directCallSiteTotal++;
                }
                List<String> targets = new ArrayList<>();
                for (Address target : flows) {
                    String targetFunctionEntry = functionEntry(target);
                    String targetFunctionName = functionName(target);
                    targets.add("{\"address\":" + json(target.toString()) +
                        ",\"function_entry\":" + (targetFunctionEntry == null ? "null" : json(targetFunctionEntry)) +
                        ",\"function_name\":" + (targetFunctionName == null ? "null" : json(targetFunctionName)) + "}");
                    if (!computed) {
                        if (targetFunctionEntry != null) {
                            directCallGraph.get(entry).add(targetFunctionEntry);
                        }
                        directCallEdges.add("{\"caller_entry\":" + json(entry) +
                            ",\"caller_name\":" + json(function.getName()) +
                            ",\"site\":" + json(site.toString()) +
                            ",\"instruction\":" + json(instruction.toString()) +
                            ",\"target\":" + json(target.toString()) +
                            ",\"callee_entry\":" + (targetFunctionEntry == null ? "null" : json(targetFunctionEntry)) +
                            ",\"callee_name\":" + (targetFunctionName == null ? "null" : json(targetFunctionName)) + "}");
                    }
                }
                String call = "{\"site\":" + json(site.toString()) +
                    ",\"instruction\":" + json(instruction.toString()) +
                    ",\"computed_or_unresolved\":" + computed +
                    ",\"targets\":[" + String.join(",", targets) +
                    "],\"data_references\":[" + String.join(",", siteDataReferences) + "]}";
                callSites.add(call);
                if (computed) {
                    String indirect = "{\"caller_entry\":" + json(entry) +
                        ",\"caller_name\":" + json(function.getName()) +
                        ",\"site\":" + json(site.toString()) +
                        ",\"instruction\":" + json(instruction.toString()) +
                        ",\"resolved_targets\":[" + String.join(",", targets) +
                        "],\"nearby_data_references\":[" + String.join(",", siteDataReferences) +
                        "],\"interpretation\":\"Static indirect-call site; target function is unresolved unless a bounded target is listed.\"}";
                    indirectSitesForFunction.add(indirect);
                    indirectCallSites.add(indirect);
                }
            }
            globalsByFunction.put(entry, globalDataReferences);

            StringBuilder inventoryItem = new StringBuilder("{");
            inventoryItem.append("\"name\":").append(json(function.getName()));
            inventoryItem.append(",\"entry\":").append(json(entry));
            inventoryItem.append(",\"body_address_count\":").append(function.getBody().getNumAddresses());
            inventoryItem.append(",\"body_ranges\":[").append(String.join(",", bodyRanges)).append("]");
            inventoryItem.append(",\"thunk\":").append(function.isThunk());
            inventoryItem.append(",\"direct_call_site_count\":").append(directCallSiteCount);
            inventoryItem.append(",\"call_sites\":[").append(String.join(",", callSites)).append("]");
            inventoryItem.append(",\"indirect_call_sites\":[").append(String.join(",", indirectSitesForFunction)).append("]");
            inventoryItem.append(",\"data_references\":[").append(String.join(",", dataReferences)).append("]");
            inventoryItem.append(",\"global_data_references\":[").append(String.join(",", globalDataReferences)).append("]}");
            functionInventory.add(inventoryItem.toString());

            ReferenceIterator referencesToFunction = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint());
            while (referencesToFunction.hasNext()) {
                Reference reference = referencesToFunction.next();
                Function caller = currentProgram.getFunctionManager().getFunctionContaining(reference.getFromAddress());
                functionCrossReferences.add("{\"target_function_entry\":" + json(entry) +
                    ",\"target_function_name\":" + json(function.getName()) +
                    ",\"from\":" + json(reference.getFromAddress().toString()) +
                    ",\"reference_type\":" + json(reference.getReferenceType().getName()) +
                    ",\"caller_entry\":" + (caller == null ? "null" : json(caller.getEntryPoint().toString())) +
                    ",\"caller_name\":" + (caller == null ? "null" : json(caller.getName())) + "}");
            }
        }

        Set<String> reachable = new LinkedHashSet<>();
        Map<String, String> predecessor = new HashMap<>();
        Map<String, Integer> depth = new HashMap<>();
        if (entryFunction != null) {
            String root = entryFunction.getEntryPoint().toString();
            Queue<String> pending = new ArrayDeque<>();
            pending.add(root);
            reachable.add(root);
            depth.put(root, 0);
            while (!pending.isEmpty()) {
                String current = pending.remove();
                for (String next : directCallGraph.getOrDefault(current, new LinkedHashSet<String>())) {
                    if (reachable.add(next)) {
                        predecessor.put(next, current);
                        depth.put(next, depth.get(current) + 1);
                        pending.add(next);
                    }
                }
            }
        }
        List<String> entryCallPaths = new ArrayList<>();
        List<String> reachableGlobalReferences = new ArrayList<>();
        for (String target : reachable) {
            List<String> path = new ArrayList<>();
            String cursor = target;
            path.add(cursor);
            while (predecessor.containsKey(cursor)) {
                cursor = predecessor.get(cursor);
                path.add(0, cursor);
            }
            entryCallPaths.add("{\"function_entry\":" + json(target) +
                ",\"function_name\":" + json(functionNamesByEntry.getOrDefault(target, "unknown")) +
                ",\"depth\":" + depth.getOrDefault(target, 0) +
                ",\"path\":[" + String.join(",", path.stream().map(ghidra_efi_summary::json).toArray(String[]::new)) +
                "],\"edge_scope\":\"direct statically resolved calls only; indirect calls are reported separately\"}");
            for (String global : globalsByFunction.getOrDefault(target, new ArrayList<String>())) {
                reachableGlobalReferences.add("{\"function_entry\":" + json(target) +
                    ",\"function_name\":" + json(functionNamesByEntry.getOrDefault(target, "unknown")) +
                    ",\"reference\":" + global + "}");
            }
        }

        List<String> instructions = new ArrayList<>();
        List<String> namedDecompilations = new ArrayList<>();
        String decompiled = "";
        String decompileStatus = "entry_function_not_found";
        if (entryFunction != null) {
            InstructionIterator iterator = currentProgram.getListing().getInstructions(entryFunction.getBody(), true);
            while (iterator.hasNext() && instructions.size() < 32) {
                Instruction instruction = iterator.next();
                instructions.add("{\"address\":" + json(instruction.getAddress().toString()) +
                    ",\"text\":" + json(instruction.toString()) + "}");
            }
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        if (entryFunction != null) {
            DecompileResults result = decompiler.decompileFunction(entryFunction, 60, new ConsoleTaskMonitor());
            if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                decompiled = result.getDecompiledFunction().getC();
                decompileStatus = "completed_static_decompilation";
            } else if (result != null && result.getErrorMessage() != null) {
                decompileStatus = "decompilation_failed: " + result.getErrorMessage();
            } else {
                decompileStatus = "decompilation_failed";
            }
        }
        FunctionIterator namedIterator = currentProgram.getFunctionManager().getFunctions(true);
        while (namedIterator.hasNext()) {
            Function function = namedIterator.next();
            if (function.getName().startsWith("FUN_") || namedDecompilations.size() >= 16) {
                continue;
            }
            DecompileResults namedResult = decompiler.decompileFunction(function, 30, new ConsoleTaskMonitor());
            String source = namedResult != null && namedResult.decompileCompleted() && namedResult.getDecompiledFunction() != null
                ? namedResult.getDecompiledFunction().getC() : "";
            namedDecompilations.add("{\"name\":" + json(function.getName()) +
                ",\"entry\":" + json(function.getEntryPoint().toString()) +
                ",\"status\":" + json(source.isEmpty() ? "decompilation_unavailable" : "completed_static_decompilation") +
                ",\"excerpt\":" + json(source.length() > 6000 ? source.substring(0, 6000) : source) + "}");
        }
        decompiler.dispose();

        StringBuilder result = new StringBuilder();
        result.append("{\n")
            .append("  \"tool\": {\"name\": \"Ghidra\", \"version\": ").append(json(args[3]))
            .append(", \"release_archive_sha256\": ").append(json(args[4])).append("},\n")
            .append("  \"input_sha256\": ").append(json(args[2])).append(",\n")
            .append("  \"program\": {\"format\": ").append(json(currentProgram.getExecutableFormat()))
            .append(", \"language\": ").append(json(currentProgram.getLanguage().getLanguageID().getIdAsString()))
            .append(", \"image_base\": ").append(json(currentProgram.getImageBase().toString()))
            .append(", \"entry_address\": ").append(json(args[1])).append("},\n")
            .append("  \"analysis\": {\"execution\": \"none; static analysis only\", \"function_count\": ")
            .append(functionCount).append(", \"non_default_named_function_count\": ").append(namedFunctionCount)
            .append(", \"direct_call_site_count\": ").append(directCallSiteTotal)
            .append(", \"entry_function_found\": ").append(entryFunction != null)
            .append(", \"entry_function_name\": ").append(entryFunction == null ? "null" : json(entryFunction.getName()))
            .append(", \"entry_function_body_bytes\": ").append(entryFunction == null ? "null" : entryFunction.getBody().getNumAddresses())
            .append(", \"entry_function_body_address_count\": ").append(entryFunction == null ? "null" : entryFunction.getBody().getNumAddresses())
            .append(", \"decompilation_status\": ").append(json(decompileStatus))
            .append(", \"entry_disassembly\": [").append(String.join(",", instructions)).append("]")
            .append(", \"entry_decompilation_excerpt\": ").append(json(decompiled.length() > 12000 ? decompiled.substring(0, 12000) : decompiled))
            .append(", \"named_functions\": [").append(String.join(",", namedFunctions)).append("]")
            .append(", \"function_inventory\": [").append(String.join(",", functionInventory)).append("]")
            .append(", \"direct_call_edges\": [").append(String.join(",", directCallEdges)).append("]")
            .append(", \"indirect_call_sites\": [").append(String.join(",", indirectCallSites)).append("]")
            .append(", \"interrupt_sites\": [").append(String.join(",", interruptSites)).append("]")
            .append(", \"function_cross_references\": [").append(String.join(",", functionCrossReferences)).append("]")
            .append(", \"entry_direct_call_paths\": [").append(String.join(",", entryCallPaths)).append("]")
            .append(", \"reachable_global_data_references\": [").append(String.join(",", reachableGlobalReferences)).append("]")
            .append(", \"named_function_decompilations\": [").append(String.join(",", namedDecompilations)).append("]")
            .append(", \"sample_functions\": [").append(String.join(",", sampleFunctions)).append("]}}")
            .append('\n');
        Files.write(output.toPath(), result.toString().getBytes(StandardCharsets.UTF_8));
        println("Wrote static code inventory to " + output.getAbsolutePath());
    }
}
