/* Exception-handling tag section (id 13): a vector of tagtype = attribute byte (0 = exception) + type index. */
package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.LEB128Info;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;

public class WasmTagSection extends WasmSection {

	private LEB128Info count;
	private List<LEB128Info> types = new ArrayList<LEB128Info>();

	public WasmTagSection(BinaryReader reader) throws IOException {
		super(reader);
		count = reader.readNext(LEB128Info::unsigned);
		for (int i = 0; i < count.asLong(); ++i) {
			reader.readNextUnsignedByte(); /* attribute */
			types.add(reader.readNext(LEB128Info::unsigned));
		}
	}

	public int getTypeIdx(int tagidx) {
		return (int) types.get(tagidx).asLong();
	}

	public int getTagCount() {
		return types.size();
	}

	@Override
	protected void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException {
		builder.addUnsignedLeb128(count, "count");
		for (int i = 0; i < types.size(); i++) {
			builder.add(BYTE, "attribute_" + i);
			builder.addUnsignedLeb128(types.get(i), "type_" + i);
		}
	}

	@Override
	public String getName() {
		return ".tag";
	}
}
