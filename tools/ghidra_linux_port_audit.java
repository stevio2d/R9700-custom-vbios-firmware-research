// Static ELF port-analysis xref/decompiler exporter; never runs target code.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import com.google.gson.GsonBuilder;
import java.nio.file.*;
import java.util.*;

public class ghidra_linux_port_audit extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Map<String,Object> report = new LinkedHashMap<>();
        report.put("program", currentProgram.getName());
        report.put("image_base", currentProgram.getImageBase().toString());
        report.put("executable_sha256", currentProgram.getExecutableSHA256());
        report.put("ghidra_version", ghidra.framework.Application.getApplicationVersion());
        Map<String,Function> selected = new TreeMap<>();
        List<Object> anchors = new ArrayList<>();
        DataIterator di = currentProgram.getListing().getDefinedData(true);
        while (di.hasNext()) {
            Data d = di.next();
            if (!(d.getValue() instanceof String)) continue;
            String s = (String)d.getValue();
            if (!s.matches("(?is).*(AMD_NAVI|amd_navi|Adapter not found|/sys/bus/pci/devices|/dev/mem|Soc15.*Sequence|SOC15 spi|PSP|[Ss]ave.*[Bb][Ii][Oo][Ss]|[Rr]ead.*[Rr][Oo][Mm]|[Rr][Oo][Mm].*[Ss]ize).*")) continue;
            Map<String,Object> a = new LinkedHashMap<>();
            a.put("address", d.getAddress().toString()); a.put("text", s);
            List<String> refs = new ArrayList<>();
            for (Reference r : getReferencesTo(d.getAddress())) {
                refs.add(r.getFromAddress().toString());
                Function f = getFunctionContaining(r.getFromAddress());
                if (f != null) selected.put(f.getEntryPoint().toString(), f);
            }
            a.put("xrefs", refs); anchors.add(a);
        }
        for (int i=1; i<args.length; i++) {
            if (args[i].equals("ALL")) {
                FunctionIterator all = currentProgram.getFunctionManager().getFunctions(true);
                while (all.hasNext()) {
                    Function f = all.next();
                    selected.put(f.getEntryPoint().toString(), f);
                }
                continue;
            }
            Address a = toAddr(args[i]);
            Function f = getFunctionAt(a);
            if (f == null) f = getFunctionContaining(a);
            if (f != null) selected.put(f.getEntryPoint().toString(), f);
        }
        report.put("anchors", anchors);
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        List<Object> functions = new ArrayList<>();
        try {
            for (Function f : selected.values()) {
                Map<String,Object> item = new LinkedHashMap<>();
                item.put("entry", f.getEntryPoint().toString()); item.put("name", f.getName());
                List<String> callers = new ArrayList<>();
                for (Reference r : getReferencesTo(f.getEntryPoint())) callers.add(r.getFromAddress().toString()+" "+r.getReferenceType());
                item.put("xrefs", callers);
                List<String> asm = new ArrayList<>();
                InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (ii.hasNext()) {
                    Instruction in = ii.next();
                    asm.add(in.getAddress()+" "+in.toString());
                }
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
