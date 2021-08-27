package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;
import wasm.format.sections.structures.WasmNameFunctionSubsection;
import wasm.format.sections.structures.WasmNameLocalSubsection;
import wasm.format.sections.structures.WasmNameModuleSubsection;
import wasm.format.sections.structures.WasmNameSubsection;
import wasm.format.sections.structures.WasmNameSubsection.WasmNameSubsectionId;;

public class WasmNameSection extends WasmCustomSection {
	private List<WasmNameSubsection> subsections = new ArrayList<>();
	private Map<WasmNameSubsectionId, WasmNameSubsection> subsectionMap = new EnumMap<>(WasmNameSubsectionId.class);

	public WasmNameSection(BinaryReader reader) throws IOException {
		super(reader);
		long sectionEnd = getSectionOffset() + getSectionSize();
		while (reader.getPointerIndex() < sectionEnd) {
			WasmNameSubsection subsection = WasmNameSubsection.createSubsection(reader);
			if (subsection == null)
				continue;
			subsections.add(subsection);
			if (subsection.getId() != null)
				subsectionMap.put(subsection.getId(), subsection);
		}
	}

	@Override
	protected void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		super.addToStructure(structure);
		for (int i = 0; i < subsections.size(); i++) {
			StructureUtils.addField(structure, subsections.get(i), subsections.get(i).getName());
		}
	}

	public String getModuleName() {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_MODULE);
		if (subsection == null)
			return null;
		return ((WasmNameModuleSubsection) subsection).getModuleName();
	}

	public String getFunctionName(int idx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_FUNCTION);
		if (subsection == null)
			return null;
		return ((WasmNameFunctionSubsection) subsection).getFunctionName(idx);
	}

	public String getLocalName(int funcidx, int localidx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_LOCAL);
		if (subsection == null)
			return null;
		return ((WasmNameLocalSubsection) subsection).getLocalName(funcidx, localidx);
	}

	@Override
	public String getName() {
		return ".name";
	}
}
