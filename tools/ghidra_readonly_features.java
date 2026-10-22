// Static export of read-only command/parser anchors; never execute vendor code.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import com.google.gson.GsonBuilder;
import java.nio.file.*;
import java.util.*;

public class ghidra_readonly_features extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Map<String,Object> report = new LinkedHashMap<>();
        report.put("program", currentProgram.getName());
        report.put("executable_sha256", currentProgram.getExecutableSHA256());
        report.put("ghidra_version", ghidra.framework.Application.getApplicationVersion());
        Map<String,Function> selected = new TreeMap<>();
        List<Object> anchors = new ArrayList<>();
        DataIterator data = currentProgram.getListing().getDefinedData(true);
        while (data.hasNext()) {
            Data d = data.next();
            if (!(d.getValue() instanceof String)) continue;
            String s = (String)d.getValue();
            if (!s.matches("(?is).*(checksum|CheckPartNumber|ComparePartNumber|checkifwi|checkpn|GetPartitionDetails|GetIFWIVersion|GetPSPBLVersion|BIOSFileInfo|GetBIOSInfo|SHA256|GetPartNumber).*")) continue;
            Map<String,Object> anchor = new LinkedHashMap<>();
            anchor.put("address", d.getAddress().toString()); anchor.put("text", s);
            List<String> refs = new ArrayList<>();
            for (Reference r : getReferencesTo(d.getAddress())) {
                refs.add(r.getFromAddress().toString());
                Function f = getFunctionContaining(r.getFromAddress());
                if (f != null) selected.put(f.getEntryPoint().toString(), f);
            }
            anchor.put("xrefs", refs); anchors.add(anchor);
        }
        for (int i = 1; i < args.length; i++) {
            Function f = getFunctionAt(toAddr(args[i]));
            if (f == null) f = getFunctionContaining(toAddr(args[i]));
            if (f == null) throw new IllegalArgumentException("Missing function: " + args[i]);
            selected.put(f.getEntryPoint().toString(), f);
        }
        Map<String,Object> comparisonLimit = new LinkedHashMap<>();
        comparisonLimit.put("address", "1407b49f4");
        comparisonLimit.put("initialized_u32", Integer.toUnsignedLong(getInt(toAddr("1407b49f4"))));
        List<String> limitRefs = new ArrayList<>();
        for (Reference r : getReferencesTo(toAddr("1407b49f4"))) {
            limitRefs.add(r.getFromAddress()+" "+r.getReferenceType());
            Function f = getFunctionContaining(r.getFromAddress());
            if (f != null) selected.put(f.getEntryPoint().toString(), f);
        }
        comparisonLimit.put("xrefs", limitRefs); report.put("part_number_comparison_limit", comparisonLimit);
        report.put("anchors", anchors);
        List<Object> functions = new ArrayList<>();
        DecompInterface decomp = new DecompInterface(); decomp.openProgram(currentProgram);
        try {
            for (Function f : selected.values()) {
                Map<String,Object> item = new LinkedHashMap<>();
                item.put("entry", f.getEntryPoint().toString()); item.put("name", f.getName());
                List<String> callers = new ArrayList<>();
                for (Reference r : getReferencesTo(f.getEntryPoint())) callers.add(r.getFromAddress()+" "+r.getReferenceType());
                item.put("xrefs", callers);
                List<String> asm = new ArrayList<>();
                InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (ii.hasNext()) { Instruction in = ii.next(); asm.add(in.getAddress()+" "+in.toString()); }
                item.put("assembly", asm);
                DecompileResults dr = decomp.decompileFunction(f, 40, monitor);
                item.put("decompiled", dr.decompileCompleted() ? dr.getDecompiledFunction().getC() : dr.getErrorMessage());
                functions.add(item);
            }
        } finally { decomp.dispose(); }
        report.put("functions", functions);
        Files.writeString(Path.of(args[0]), new GsonBuilder().setPrettyPrinting().create().toJson(report)+"\n",
                          StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }
}
