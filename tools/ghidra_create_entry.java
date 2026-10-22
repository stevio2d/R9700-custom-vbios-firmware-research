// Create a user-specified static-analysis entry point before Ghidra auto-analysis.
// This is used for raw option-ROM images whose entry is described by the ROM header.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class ghidra_create_entry extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("Usage: ghidra_create_entry.java <entry-address>");
        }
        Address entry = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(args[0]);
        Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
        if (function == null) {
            disassemble(entry);
            function = createFunction(entry, "entry");
        }
        if (function == null) {
            throw new IllegalStateException("Could not create a function at static entry " + entry);
        }
        println("Prepared static entry function at " + function.getEntryPoint());
    }
}
