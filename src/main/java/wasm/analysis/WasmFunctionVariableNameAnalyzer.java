package wasm.analysis;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighLocal;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import wasm.format.WasmEnums.ValType;
import wasm.format.sections.WasmNameSection;
import wasm.format.sections.structures.WasmNameSubsection.WasmNameSubsectionId;

public class WasmFunctionVariableNameAnalyzer extends AbstractAnalyzer {

	private final static int MAX_LOCAL = 4096;

	private final static String DESCRIPTION = "Extract and apply names contained in the '.name' section to functions' local variables.";

	private DecompInterface dif;
	/** offset to the first local in the register space **/
	private long baseLocalOffset;

	public WasmFunctionVariableNameAnalyzer() {
		super("Wasm variable name Analyzer", DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(Processor.findOrPossiblyCreateProcessor("Webassembly"));
	}

	protected DecompInterface getInitializedDecompInterface(Program prog) {
		if (dif == null) {
			dif = new DecompInterface();
			dif.openProgram(prog);
		}
		return dif;
	}

	protected void cleanup() {
		if (dif != null) {
			dif.dispose();
			dif = null;
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		WasmAnalysis state = WasmAnalysis.getState(program);
		WasmNameSection nameSection = state.getModule().getNameSection();
		if (nameSection == null) {
			return true;
		}

		// skip if the name section doesn't contain a NAME_LOCAL entry.
		if (!nameSection.hasNameSubSection(WasmNameSubsectionId.NAME_LOCAL)) {
			return true;
		}

		baseLocalOffset = program.getRegister("l0q").getOffset();

		try {
			FunctionIterator iter = program.getFunctionManager().getFunctions(set, true);
			while (iter.hasNext()) {
				if (monitor.isCancelled()) {
					break;
				}

				Function func = iter.next();
				WasmFuncSignature funcSig = state.getFunctionByAddress(func.getEntryPoint());
				if (funcSig == null) {
					// this should never happen
					continue;
				}
				Map<Long, String> localNames = nameSection.getLocalNames(funcSig.getFuncidx());
				if (localNames == null || localNames.isEmpty()) {
					continue;
				}

				Map<Long, String> filteredLocalNames = filterNewVariables(func, funcSig, localNames);
				if (filteredLocalNames.isEmpty()) {
					// skip if there is no name to apply after filtering
					continue;
				}
				applyLocalNames(program, func, funcSig, filteredLocalNames);
			}
		} finally {
			cleanup();
		}
		return true;
	}

	protected Map<Long, String> filterNewVariables(Function func, WasmFuncSignature funcSig,
			Map<Long, String> localNames) {
		// compute variable names and local indexes that are already assigned
		Set<String> usedVarNames = new HashSet<>();
		Set<Long> usedLocalIndexes = new HashSet<>();
		for (Variable var : func.getLocalVariables()) {
			usedVarNames.add(var.getName());
			Varnode vn = var.getFirstStorageVarnode();
			if (vn.isRegister()) {
				long localIndex = registerToLocal(vn.getOffset());
				if (localIndex != -1) {
					usedLocalIndexes.add(localIndex);
				}
			}
		}

		int paramsCount = funcSig.getParams().length;

		Map<Long, String> filteredLocalNames = new HashMap<>();
		for (Entry<Long, String> entry : localNames.entrySet()) {
			long localIndex = entry.getKey();
			String localName = entry.getValue();
			// skip if this entry corresponds to a function parameter
			if (localIndex < paramsCount) {
				continue;
			}

			// there are at most 4096 locals (as defined in the slaspec file).
			if (localIndex >= MAX_LOCAL) {
				continue;
			}

			// skip if there is already a variable defined for this local
			if (usedLocalIndexes.contains(localIndex)) {
				continue;
			}

			// skip if there is already a variable with the same name
			if (usedVarNames.contains(localName)) {
				continue;
			}
			filteredLocalNames.put(localIndex, localName);
		}

		return filteredLocalNames;
	}

	protected void applyLocalNames(Program program, Function function, WasmFuncSignature funcSig,
			Map<Long, String> localNames) {
		Set<Long> localIndexes = new HashSet<>(localNames.keySet()); // make a copy as found elements will be removed
		Map<Long, Long> localsFirstUse = getLocalFirstUses(program, function, localIndexes);

		ValType[] localsTypes = funcSig.getLocals();

		int paramCount = funcSig.getParams().length;

		for (Entry<Long, String> entry : localNames.entrySet()) {
			long localIndex = entry.getKey();
			String varName = entry.getValue();
			long firstUse = localsFirstUse.getOrDefault(localIndex, 0l);
			DataType dt = localsTypes[(int) (localIndex - paramCount)].asDataType();
			Register reg = program.getLanguage().getRegister(getRegisterName(localIndex, dt.getLength()));

			try {
				LocalVariableImpl var = new LocalVariableImpl(varName, (int) firstUse, dt, reg, program);
				function.addLocalVariable(var, SourceType.ANALYSIS);
			} catch (InvalidInputException | DuplicateNameException e) {
				Msg.error(this, "Failed to apply variable name '" + varName + "' to " + function.getName(), e);
			}
		}
	}

	protected Map<Long, Long> getLocalFirstUses(Program prog, Function func, Set<Long> localIndexSearch) {
		// Note:
		// We retrieve first uses of local using the decompiler to make sure
		// that it picks up the new variable name. Otherwise, the variable name is only
		// shown in listing.

		Map<Long, Long> res = new HashMap<>();
		// create or reuse existing DecompInterface
		DecompInterface decomp = getInitializedDecompInterface(prog);
		// decompile the function
		HighFunction hf = decomp.decompileFunction(func, 10, null).getHighFunction();

		// loop through HighSymbol to retrieve variable corresponding to a local
		Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols();
		while (it.hasNext() && !localIndexSearch.isEmpty()) {
			HighSymbol hs = it.next();
			HighVariable hv = hs.getHighVariable();
			if (hv == null) {
				continue;
			}
			Varnode vn = hv.getRepresentative();
			if (vn.isRegister() && hv instanceof HighLocal) {
				long localIndex = registerToLocal(vn.getOffset());
				// if this is one of the locals we are looking for
				if (localIndexSearch.contains(localIndex)) {
					HighLocal hl = (HighLocal) hv;
					long useOffset = hl.getPCAddress().getOffset() - func.getEntryPoint().getOffset();
					res.put(localIndex, useOffset);
					// no need to keep looking for this local
					localIndexSearch.remove(localIndex);
				}

			}
		}
		return res;
	}

	protected long registerToLocal(long registerOffset) {
		long localIndex = (registerOffset - baseLocalOffset) / 8;
		if (localIndex < 0 || localIndex >= MAX_LOCAL) {
			return -1;
		}
		return localIndex;
	}

	protected String getRegisterName(long localIndex, int dataSize) {
		return "l" + localIndex + (dataSize == 8 ? "q" : "");
	}

}