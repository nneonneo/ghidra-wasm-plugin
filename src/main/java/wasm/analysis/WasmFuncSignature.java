package wasm.analysis;

import ghidra.program.model.address.Address;
import wasm.format.WasmEnums.ValType;

public class WasmFuncSignature {
	private int funcidx;
	private ValType[] params;
	private ValType[] returns;
	private String name;
	private Address startAddr;
	private Address endAddr; // address of last byte in the function (inclusive)
	private ValType[] locals;

	public int getFuncidx() {
		return funcidx;
	}

	public ValType[] getParams() {
		return params;
	}

	public ValType[] getReturns() {
		return returns;
	}

	public ValType[] getLocals() {
		return locals;
	}

	public String getName() {
		return name;
	}

	public Address getStartAddr() {
		return startAddr;
	}

	public Address getEndAddr() {
		return endAddr;
	}

	public boolean isImport() {
		return locals == null;
	}

	public WasmFuncSignature(int funcidx, ValType[] paramTypes, ValType[] returnTypes, String name, Address addr) {
		this.funcidx = funcidx;
		this.name = name;
		this.startAddr = addr;
		this.params = paramTypes;
		this.returns = returnTypes;
	}

	public WasmFuncSignature(int funcidx, ValType[] paramTypes, ValType[] returnTypes, String name, Address startAddr,
			Address endAddr, ValType[] locals) {
		this(funcidx, paramTypes, returnTypes, name, startAddr);
		this.endAddr = endAddr;
		this.locals = locals;
	}

	@Override
	public String toString() {
		return String.format("%s @ %s %dT -> %dT", name, startAddr.toString(), params.length, returns.length);
	}
}
