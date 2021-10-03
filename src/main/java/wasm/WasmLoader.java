/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package wasm;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import wasm.format.WasmConstants;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.WasmHeader;
import wasm.format.WasmModule;
import wasm.format.sections.WasmNameSection;
import wasm.format.sections.WasmSection;
import wasm.format.sections.WasmSection.WasmSectionId;
import wasm.format.sections.structures.WasmDataSegment;
import wasm.format.sections.structures.WasmElementSegment;
import wasm.format.sections.structures.WasmExportEntry;
import wasm.format.sections.structures.WasmFunctionBody;
import wasm.format.sections.structures.WasmGlobalEntry;
import wasm.format.sections.structures.WasmGlobalType;
import wasm.format.sections.structures.WasmImportEntry;
import wasm.format.sections.structures.WasmResizableLimits;
import wasm.format.sections.structures.WasmTableType;

public class WasmLoader extends AbstractLibrarySupportLoader {

	public final static long CODE_BASE = 0x80000000L;

	@Override
	public String getName() {
		return "WebAssembly";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);
		WasmHeader header = new WasmHeader(reader);

		if (Arrays.equals(WasmConstants.WASM_MAGIC, header.getMagic()) && WasmConstants.WASM_VERSION == header.getVersion()) {
			loadSpecs.add(new LoadSpec(this, CODE_BASE, new LanguageCompilerSpecPair("Wasm:LE:32:default", "default"), true));
		}

		return loadSpecs;
	}

	// #region Address computations
	public static long getFunctionAddressOffset(WasmModule module, int funcidx) {
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_FUNCTION);
		if (funcidx < imports.size()) {
			return CODE_BASE + imports.get(funcidx).getEntryOffset();
		} else {
			WasmFunctionBody functionBody = module.getNonImportedFunctionBodies().get(funcidx - imports.size());
			return CODE_BASE + functionBody.getOffset();
		}
	}

	public static long getFunctionSize(Program program, WasmModule module, int funcidx) {
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_FUNCTION);
		if (funcidx < imports.size()) {
			return imports.get(funcidx).getEntrySize();
		} else {
			WasmFunctionBody functionBody = module.getNonImportedFunctionBodies().get(funcidx - imports.size());
			return functionBody.getInstructions().length;
		}
	}

	public static Address getFunctionAddress(Program program, WasmModule module, int funcidx) {
		return program.getAddressFactory().getAddressSpace("ram").getAddress(getFunctionAddressOffset(module, funcidx));
	}

	public static Address getTableAddress(Program program, int tableidx, long itemIndex) {
		return program.getAddressFactory().getAddressSpace("table").getAddress((((long) tableidx) << 32) + (itemIndex * 8));
	}

	public static Address getMemoryAddress(Program program, int memidx, long offset) {
		if (memidx != 0) {
			/* only handle memory 0 for now */
			throw new IllegalArgumentException("non-zero memidx is not supported");
		}

		return program.getAddressFactory().getAddressSpace("ram").getAddress(offset);
	}

	public static Address getGlobalAddress(Program program, int globalidx) {
		return program.getAddressFactory().getAddressSpace("global").getAddress(((long) globalidx) * 8);
	}

	private static Address getCodeAddress(Program program, long fileOffset) {
		return program.getAddressFactory().getAddressSpace("ram").getAddress(CODE_BASE + fileOffset);
	}
	// #endregion

	// #region Naming
	private static Namespace getNamespace(Program program, Namespace parent, String name) {
		try {
			return program.getSymbolTable().getOrCreateNameSpace(parent, name, SourceType.IMPORTED);
		} catch (Exception e) {
			return parent;
		}
	}

	private static Namespace getObjectNamespace(Program program, WasmModule module, WasmExternalKind objectKind, int objidx) {
		Namespace globalNamespace = program.getGlobalNamespace();

		List<WasmImportEntry> imports = module.getImports(objectKind);
		if (objidx < imports.size()) {
			Namespace importNamespace = getNamespace(program, globalNamespace, "import");
			return getNamespace(program, importNamespace, imports.get(objidx).getModule());
		}
		WasmExportEntry entry = module.findExport(objectKind, objidx);
		if (entry != null) {
			return getNamespace(program, globalNamespace, "export");
		}
		return globalNamespace;
	}

	private static String getObjectName(Program program, WasmModule module, WasmExternalKind objectKind, int objidx) {
		List<WasmImportEntry> imports = module.getImports(objectKind);
		if (objidx < imports.size()) {
			return imports.get(objidx).getName();
		}
		WasmExportEntry entry = module.findExport(objectKind, objidx);
		if (entry != null) {
			return entry.getName();
		}
		return null;
	}

	public static Namespace getFunctionNamespace(Program program, WasmModule module, int funcidx) {
		return getObjectNamespace(program, module, WasmExternalKind.EXT_FUNCTION, funcidx);
	}

	public static String getFunctionName(Program program, WasmModule module, int funcidx) {
		String name;
		WasmNameSection nameSection = module.getNameSection();
		if (nameSection != null) {
			name = nameSection.getFunctionName(funcidx);
			if (name != null) {
				return name;
			}
		}
		name = getObjectName(program, module, WasmExternalKind.EXT_FUNCTION, funcidx);
		if (name != null) {
			return name;
		}
		return "unnamed_function_" + funcidx;
	}

	public static Namespace getGlobalNamespace(Program program, WasmModule module, int globalidx) {
		return getObjectNamespace(program, module, WasmExternalKind.EXT_GLOBAL, globalidx);
	}

	public static String getGlobalName(Program program, WasmModule module, int globalidx) {
		String name;
		WasmNameSection nameSection = module.getNameSection();
		if (nameSection != null) {
			name = nameSection.getGlobalName(globalidx);
			if (name != null) {
				return name;
			}
		}
		name = getObjectName(program, module, WasmExternalKind.EXT_GLOBAL, globalidx);
		if (name != null) {
			return name;
		}
		return "global_" + globalidx;
	}
	// #endregion

	// #region Memory blocks
	private static Data createData(Program program, Listing listing, Address address, DataType dt) {
		try {
			Data d = listing.getDataAt(address);
			if (d == null || !dt.isEquivalent(d.getDataType())) {
				d = DataUtilities.createData(program, address, dt, -1, false,
						ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			return d;
		} catch (CodeUnitInsertionException e) {
			Msg.warn(WasmLoader.class, "Data markup conflict at " + address, e);
		} catch (DataTypeConflictException e) {
			Msg.error(WasmLoader.class, "Data type markup conflict:" + e.getMessage(), e);
		}
		return null;
	}

	private static MemoryBlock createModuleBlock(Program program, FileBytes fileBytes) throws Exception {
		Address start = AddressSpace.OTHER_SPACE.getAddress(0L);
		MemoryBlock block = program.getMemory().createInitializedBlock(".module", start, fileBytes, 0, fileBytes.getSize(), false);
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(false);
		block.setSourceName("Wasm Module");
		block.setComment("The full file contents of the Wasm module");
		return block;
	}

	private static void createImportStubBlock(Program program, Address startAddress, long length) {
		try {
			MemoryBlock block = program.getMemory().createUninitializedBlock(MemoryBlock.EXTERNAL_BLOCK_NAME, startAddress, length, false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(true);
			block.setComment("NOTE: This block is artificial and is used to represent imported functions");
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create imported function block at " + startAddress, e);
		}
	}

	private static void createFunctionBodyBlock(Program program, FileBytes fileBytes, long fileOffset, Address startAddress, long length) {
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(".function", startAddress, fileBytes, fileOffset, length, false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(true);
			block.setSourceName("Wasm Function");
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create function block at " + startAddress, e);
		}
	}

	private static void createTableBlock(Program program, DataType elementDataType, long numElements, int tableidx, TaskMonitor monitor) {
		long byteSize = elementDataType.getLength() * numElements;
		Address dataStart = getTableAddress(program, tableidx, 0);
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(".table" + tableidx, dataStart, byteSize, (byte) 0xff, monitor, false);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
			DataType tableDataType = new ArrayDataType(elementDataType, (int) numElements, elementDataType.getLength());
			createData(program, program.getListing(), dataStart, tableDataType);
			program.getSymbolTable().createLabel(dataStart, "table" + tableidx, SourceType.IMPORTED);
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create table block " + tableidx + " at " + dataStart, e);
		}
	}

	private static void createMemoryBlock(Program program, int memidx, long length, TaskMonitor monitor) {
		Address dataStart = getMemoryAddress(program, memidx, 0);
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(".memory" + memidx, dataStart, length, (byte) 0x00, monitor, false);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
			block.setSourceName("Wasm Memory");
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create memory block " + memidx + " at " + dataStart, e);
		}
	}

	private static void createGlobalBlock(Program program, DataType dataType, byte[] initBytes, int globalidx, int mutability, TaskMonitor monitor) {
		Address dataStart = getGlobalAddress(program, globalidx);
		try {
			MemoryBlock block;
			if (initBytes == null) {
				block = program.getMemory().createUninitializedBlock(".global" + globalidx, dataStart, dataType.getLength(), false);
			} else {
				block = program.getMemory().createInitializedBlock(".global" + globalidx, dataStart, dataType.getLength(), (byte) 0xff, monitor, false);
				program.getMemory().setBytes(dataStart, initBytes);
			}
			block.setRead(true);
			block.setWrite((mutability != 0) ? true : false);
			block.setExecute(false);
			createData(program, program.getListing(), dataStart, dataType);
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create global block " + globalidx + " at " + dataStart);
		}
	}
	// #endregion

	private void loadFunctions(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		monitor.setMessage("Loading functions");
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_FUNCTION);
		List<WasmFunctionBody> functionBodies = module.getNonImportedFunctionBodies();
		int numFunctions = imports.size() + functionBodies.size();

		/*
		 * Create two memory blocks to hold the imported and non-imported functions.
		 * While it would be cleaner (in memory) to load each function into its own
		 * block, this can cause massive slowdowns for files with many functions.
		 */
		WasmSection importSection = module.getSection(WasmSectionId.SEC_IMPORT);
		if (importSection != null) {
			createImportStubBlock(program, getCodeAddress(program, importSection.getSectionOffset()), importSection.getSectionSize());
		}
		WasmSection codeSection = module.getSection(WasmSectionId.SEC_CODE);
		if (codeSection != null) {
			long codeOffset = codeSection.getSectionOffset();
			createFunctionBodyBlock(program, fileBytes, codeOffset, getCodeAddress(program, codeOffset), codeSection.getSectionSize());
		}

		monitor.initialize(numFunctions);
		for (int funcidx = 0; funcidx < numFunctions; funcidx++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			Address startAddress = getFunctionAddress(program, module, funcidx);
			long functionLength = getFunctionSize(program, module, funcidx);
			String functionName = getFunctionName(program, module, funcidx);
			Namespace functionNamespace = getFunctionNamespace(program, module, funcidx);

			try {
				program.getFunctionManager().createFunction(functionName, functionNamespace,
						startAddress, new AddressSet(startAddress, startAddress.add(functionLength - 1)), SourceType.IMPORTED);
				program.getSymbolTable().createLabel(startAddress, functionName, functionNamespace, SourceType.IMPORTED);
			} catch (Exception e) {
				Msg.error(this, "Failed to create function index " + funcidx + " (" + functionName + ") at " + startAddress, e);
			}
		}
	}

	private void loadTables(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		monitor.setMessage("Loading tables");
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_TABLE);
		List<WasmTableType> tables = module.getNonImportedTables();
		int numTables = imports.size() + tables.size();

		monitor.initialize(numTables);
		for (int tableidx = 0; tableidx < numTables; tableidx++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			WasmTableType table;
			if (tableidx < imports.size()) {
				table = imports.get(tableidx).getTableType();
			} else {
				table = tables.get(tableidx - imports.size());
			}

			createTableBlock(program, table.getElementDataType(), table.getLimits().getInitial(), tableidx, monitor);
		}
	}

	/**
	 * Copy element segment to table.
	 * 
	 * This is public so that it can be called after loading, e.g. to load a passive
	 * element segment once the dynamic table index and offset are known.
	 *
	 * For example, this could be called from a script as follows:
	 * 
	 * WasmLoader.loadElementsToTable(getCurrentProgram(),
	 * WasmAnalysis.getState(getCurrentProgram()).getModule(), elemidx, tableidx,
	 * offset, new ConsoleTaskMonitor())
	 */
	public static void loadElementsToTable(Program program, WasmModule module, int elemidx, int tableidx, long offset, TaskMonitor monitor) throws Exception {
		WasmElementSegment elemSegment = module.getElementSegments().get(elemidx);

		byte[] initBytes = elemSegment.getInitData(module);
		if (initBytes == null)
			return;

		program.getMemory().setBytes(getTableAddress(program, tableidx, offset), initBytes);

		Address[] refs = elemSegment.getAddresses(program, module);
		for (int i = 0; i < refs.length; i++) {
			if (refs[i] != null) {
				Address elementAddr = getTableAddress(program, tableidx, offset + i);
				program.getReferenceManager().removeAllReferencesFrom(elementAddr);
				program.getReferenceManager().addMemoryReference(elementAddr, refs[i], RefType.DATA, SourceType.IMPORTED, 0);
			}
		}
	}

	private void loadElementSegments(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		/* Load active element segments into tables */
		monitor.setMessage("Loading table elements");
		List<WasmElementSegment> entries = module.getElementSegments();

		monitor.initialize(entries.size());
		for (int elemidx = 0; elemidx < entries.size(); elemidx++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			WasmElementSegment elemSegment = entries.get(elemidx);
			int tableidx = (int) elemSegment.getTableIndex();

			Long offset = elemSegment.getOffset();
			if (offset == null)
				continue;

			try {
				loadElementsToTable(program, module, elemidx, tableidx, offset, monitor);
			} catch (Exception e) {
				Msg.error(this, "Failed to initialize table " + tableidx + " with element segment " + elemidx + " at offset " + offset, e);
			}
		}
	}

	private void loadMemories(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		monitor.setMessage("Loading memories");
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_MEMORY);
		List<WasmResizableLimits> memories = module.getNonImportedMemories();
		int numMemories = imports.size() + memories.size();

		monitor.initialize(numMemories);
		for (int memidx = 0; memidx < numMemories; memidx++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			if (memidx != 0) {
				/* only handle memory 0 for now */
				continue;
			}
			WasmResizableLimits mem;
			if (memidx < imports.size()) {
				mem = imports.get(memidx).getMemoryType();
			} else {
				mem = memories.get(memidx - imports.size());
			}
			createMemoryBlock(program, memidx, Math.min(mem.getInitial() * 65536L, CODE_BASE), monitor);
		}
	}

	/**
	 * Copy data segment to memory.
	 * 
	 * This is public so that it can be called after loading, e.g. to load a passive
	 * data segment once the dynamic memory index and offset are known.
	 *
	 * For example, this could be called from a script as follows:
	 * 
	 * WasmLoader.loadDataToMemory(getCurrentProgram(),
	 * WasmAnalysis.getState(getCurrentProgram()).getModule(), dataidx, memidx,
	 * offset, new ConsoleTaskMonitor())
	 */
	public static void loadDataToMemory(Program program, WasmModule module, int dataidx, int memidx, long offset, TaskMonitor monitor) throws Exception {
		WasmDataSegment dataSegment = module.getDataSegments().get(dataidx);
		Address memStart = getMemoryAddress(program, memidx, offset);
		program.getMemory().setBytes(memStart, dataSegment.getData());
	}

	private void loadDataSegments(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		/* Load active data segments into memory */
		monitor.setMessage("Loading data segments");
		List<WasmDataSegment> dataSegments = module.getDataSegments();

		monitor.initialize(dataSegments.size());
		for (int dataidx = 0; dataidx < dataSegments.size(); dataidx++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			WasmDataSegment dataSegment = dataSegments.get(dataidx);
			int memidx = (int) dataSegment.getIndex();
			if (memidx != 0) {
				/* only handle memory 0 for now */
				continue;
			}

			Long offset = dataSegment.getMemoryOffset();
			if (offset == null) {
				continue;
			}

			try {
				loadDataToMemory(program, module, dataidx, memidx, offset, monitor);
			} catch (Exception e) {
				Address memStart = getMemoryAddress(program, memidx, offset);
				Msg.error(this, "Failed to initialize memory " + memidx + " with data segment " + dataidx + " at " + memStart, e);
			}
		}
	}

	private void loadGlobals(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		monitor.setMessage("Loading globals");
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_GLOBAL);
		List<WasmGlobalEntry> globals = module.getNonImportedGlobals();
		int numGlobals = imports.size() + globals.size();

		monitor.initialize(numGlobals);
		for (int globalidx = 0; globalidx < numGlobals; globalidx++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			WasmGlobalType globalType;
			byte[] initBytes;
			Address initRef;
			Long initGlobal;
			if (globalidx < imports.size()) {
				globalType = imports.get(globalidx).getGlobalType();
				initBytes = null;
				initRef = null;
				initGlobal = null;
			} else {
				WasmGlobalEntry entry = globals.get(globalidx - imports.size());
				globalType = entry.getGlobalType();
				initBytes = entry.asBytes(module);
				initRef = entry.asAddress(program, module);
				initGlobal = entry.asGlobalGet();
			}

			createGlobalBlock(program, globalType.getType().asDataType(), initBytes, globalidx, globalType.getMutability(), monitor);

			Address dataStart = getGlobalAddress(program, globalidx);
			Namespace namespace = getGlobalNamespace(program, module, globalidx);
			String name = getGlobalName(program, module, globalidx);
			try {
				program.getSymbolTable().createLabel(dataStart, name, namespace, SourceType.IMPORTED);
			} catch (Exception e) {
				Msg.error(this, "Failed to label global " + globalidx + " (" + name + ") at " + dataStart, e);
			}

			if (initRef != null) {
				program.getReferenceManager().removeAllReferencesFrom(dataStart);
				program.getReferenceManager().addMemoryReference(dataStart, initRef, RefType.DATA, SourceType.IMPORTED, 0);
			}
			if (initGlobal != null) {
				int commentType = CodeUnit.PLATE_COMMENT;
				String currentComment = program.getListing().getComment(commentType, dataStart);
				if (currentComment == null) {
					currentComment = "";
				} else if (!currentComment.isEmpty()) {
					currentComment += "\n";
				}
				Address otherAddress = getGlobalAddress(program, (int) (long) initGlobal);
				program.getListing().setComment(dataStart, commentType, currentComment + "Initializer: {@symbol " + otherAddress + "}");
			}
		}
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log) throws IOException {

		monitor.setMessage("Start loading");

		try {
			doLoad(provider, program, monitor);
		} catch (Exception e) {
			monitor.setMessage("Error");
			Msg.error(this, "Failed to load Wasm module", e);
		}
	}

	private void doLoad(ByteProvider provider, Program program, TaskMonitor monitor) throws Exception {
		BinaryReader reader = new BinaryReader(provider, true);
		WasmModule module = new WasmModule(reader);

		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, 0, provider.length(), monitor);

		MemoryBlock moduleBlock = createModuleBlock(program, fileBytes);
		createData(program, program.getListing(), moduleBlock.getStart(), module.getHeader().toDataType());

		for (WasmSection section : module.getSections()) {
			monitor.setMessage("Creating section " + section.getName());
			createData(program, program.getListing(), moduleBlock.getStart().add(section.getSectionOffset()), section.toDataType());
		}

		loadFunctions(program, fileBytes, module, monitor);
		loadTables(program, fileBytes, module, monitor);
		loadElementSegments(program, fileBytes, module, monitor);
		loadMemories(program, fileBytes, module, monitor);
		loadDataSegments(program, fileBytes, module, monitor);
		loadGlobals(program, fileBytes, module, monitor);
	}
}
