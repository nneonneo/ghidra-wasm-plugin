package wasm.format.sections.structures;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.ValType;

public class WasmFunctionBody implements StructConverter {

	private LEB128 bodySize;
	private List<WasmLocalEntry> locals = new ArrayList<WasmLocalEntry>();
	private LEB128 localCount;
	private long codeOffset;
	private byte[] instructions;

	public WasmFunctionBody(BinaryReader reader) throws IOException {
		bodySize = LEB128.readUnsignedValue(reader);
		codeOffset = reader.getPointerIndex();
		localCount = LEB128.readUnsignedValue(reader);
		for (int i = 0; i < localCount.asLong(); ++i) {
			locals.add(new WasmLocalEntry(reader));
		}
		int instructionOffset = (int) reader.getPointerIndex();
		instructions = reader.readNextByteArray((int) (codeOffset + bodySize.asLong() - instructionOffset));
	}

	public long getBodySize() {
		return bodySize.asLong();
	}

	public long getOffset() {
		return codeOffset;
	}

	public byte[] getInstructions() {
		return instructions;
	}

	public ValType[] getLocals() {
		int localCount = 0;
		for (WasmLocalEntry local : locals) {
			localCount += local.getCount();
		}
		ValType[] result = new ValType[localCount];
		int pos = 0;
		for (WasmLocalEntry local : locals) {
			Arrays.fill(result, pos, pos + local.getCount(), ValType.fromByte(local.getType()));
			pos += local.getCount();
		}
		return result;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("function_body_" + codeOffset);
		builder.add(bodySize, "body_size");
		builder.add(localCount, "local_count");
		for (int i = 0; i < localCount.asLong(); i++) {
			builder.add(locals.get(i).toDataType(), "compressed_locals_" + i);
		}
		builder.addArray(BYTE, instructions.length, "instructions");
		return builder.toStructure();
	}
}
