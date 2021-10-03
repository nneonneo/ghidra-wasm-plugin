package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;

public abstract class WasmNameSubsection implements StructConverter {

	protected int id;
	private LEB128 contentLength;
	private long sectionOffset;

	public static interface WasmNameSubsectionId {
		public static final int NAME_MODULE = 0;
		public static final int NAME_FUNCTION = 1;
		public static final int NAME_LOCAL = 2;
		public static final int NAME_GLOBAL = 7;
		public static final int NAME_DATA = 9;
	}

	public static WasmNameSubsection createSubsection(BinaryReader reader) throws IOException {
		long sectionOffset = reader.getPointerIndex();
		int id = reader.readNextUnsignedByte();
		LEB128 contentLength = LEB128.readUnsignedValue(reader);
		reader.setPointerIndex(reader.getPointerIndex() + contentLength.asLong());

		BinaryReader sectionReader = reader.clone(sectionOffset);

		switch (id) {
		case WasmNameSubsectionId.NAME_MODULE:
			return new WasmNameModuleSubsection(sectionReader);
		case WasmNameSubsectionId.NAME_FUNCTION:
			return new WasmNameMapSubsection("function", sectionReader);
		case WasmNameSubsectionId.NAME_LOCAL:
			return new WasmNameLocalSubsection(sectionReader);
		case WasmNameSubsectionId.NAME_GLOBAL:
			return new WasmNameMapSubsection("global", sectionReader);
		case WasmNameSubsectionId.NAME_DATA:
			return new WasmNameMapSubsection("data", sectionReader);
		default:
			return new WasmNameUnknownSubsection(sectionReader);
		}
	}

	protected WasmNameSubsection(BinaryReader reader) throws IOException {
		sectionOffset = reader.getPointerIndex();
		id = reader.readNextUnsignedByte();
		contentLength = LEB128.readUnsignedValue(reader);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder(getName());
		builder.add(BYTE, "id");
		builder.add(contentLength, "size");
		addToStructure(builder);
		return builder.toStructure();
	}

	public abstract String getName();

	protected abstract void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException;

	public int getId() {
		return id;
	}

	public long getSectionOffset() {
		return sectionOffset;
	}

	public long getContentSize() {
		return contentLength.asLong();
	}

	public long getSectionSize() {
		return 1 + contentLength.getLength() + contentLength.asLong();
	}
}
