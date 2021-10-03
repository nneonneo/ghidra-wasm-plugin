package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;

/**
 * Common class for functions/globals/data names subsection
 */
public class WasmNameMapSubsection extends WasmNameSubsection {
	private String entityName;
	private WasmNameMap nameMap;

	public WasmNameMapSubsection(String entityName, BinaryReader reader) throws IOException {
		super(reader);
		this.entityName = entityName;
		nameMap = new WasmNameMap(entityName + "_namemap",reader);
	}

	public String getName(long idx) {
		return nameMap.getEntry(idx);
	}

	@Override
	public void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException {
		builder.add(nameMap, entityName + "_names");
	}

	@Override
	public String getName() {
		return ".name." + entityName;
	}
}
