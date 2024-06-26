## ###
#  IP: GHIDRA
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#       http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##

# A script to test the WebAssembly emulator against a .wast test suite.
# As input, provide the .json file generated by wast2json.
# It is recommended to run this script headless, as follows:
# analyzeHeadless <projDir> <projName> -preScript spectest.py <test.json>
# @author nneonneo
# @category Analysis.Wasm
# @keybinding
# @menupath
# @toolbar
from __future__ import print_function
import os
import sys
import json
import struct

from java.io import File
from java.math import BigInteger
from ghidra.app.emulator import EmulatorHelper
from ghidra.app.plugin.core.analysis import AutoAnalysisManager
from ghidra.program.emulation import WasmEmulationHelper
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.listing import Program
from wasm import WasmLoader
from wasm.analysis import WasmAnalysis

## Ensure output is not buffered
class Unbuffered(object):
   def __init__(self, stream):
       self.stream = stream
   def write(self, data):
       self.stream.write(data)
       self.stream.flush()
   def writelines(self, datas):
       self.stream.writelines(datas)
       self.stream.flush()
   def __getattr__(self, attr):
       return getattr(self.stream, attr)

sys.stdout = Unbuffered(sys.stdout)
sys.stderr = Unbuffered(sys.stderr)
eprint = lambda *args, **kwargs: print(*args, file=sys.stderr, **kwargs)

"""
Command schema (https://github.com/WebAssembly/wabt/blob/main/docs/wast2json.md):

"module" 	{..., "name": <string>, "filename": <string>}
"action" 	{..., "action": <action>}
"assert_return" 	{..., "action": <action>, "expected": <expected>}
"assert_exhaustion" 	{..., "action": <action>, "text": <string>}
"assert_trap" 	{..., "action": <action>, "text": <string>}
"assert_invalid" 	{..., "filename": <string>, "text": <string>, "module_type": <module_type>}
"assert_malformed" 	{..., "filename": <string>, "text": <string>, "module_type": <module_type>}
"assert_uninstantiable" 	{..., "filename": <string>, "text": <string>, "module_type": <module_type>}
"assert_unlinkable" 	{..., "filename": <string>, "text": <string>, "module_type": <module_type>}
"register" 	{..., "name": <string>, "as": <string>}
"""

null_val = 0x00000000
# return address for the top-level function call
ret_addr = 0x80000000

class EmulationError(Exception):
    pass

def parse_ref(eit, eiv):
    if eiv == "null":
        return 0
    if eit in ("externref", "exnref"):
        # 0x0 is reserved for null, so we arbitrarily choose a nonzero encoding
        # for externref objects. (This is essentially a host environment choice)
        assert int(eiv) < 0x80000000
        return 0x80000000 + int(eiv)
    # this shouldn't actually happen: funcref is opaque to the host environment
    # so wast commands should only be testing against funcref null
    return int(eiv)

def encode_arg(ei):
    eit = ei["type"]
    eiv = ei["value"]
    if eit in ("i32", "f32"):
        return struct.pack("<I", int(eiv))
    elif eit in ("i64", "f64"):
        return struct.pack("<Q", int(eiv))
    elif eit in ("externref", "funcref", "exnref"):
        return struct.pack("<I", parse_ref(eit, eiv))
    elif eit == "v128":
        eilt = ei["lane_type"]
        if eilt == "i8":
            return struct.pack("<16B", *[int(c) for c in eiv])
        elif eilt == "i16":
            return struct.pack("<8H", *[int(c) for c in eiv])
        elif eilt in ("i32", "f32"):
            return struct.pack("<4I", *[int(c) for c in eiv])
        elif eilt in ("i64", "f64"):
            return struct.pack("<2Q", *[int(c) for c in eiv])
        else:
            raise Exception("unknown lane type %s" % eilt)
    else:
        raise Exception("unknown value type %s" % eit)

class EmulatedProgram(FlatProgramAPI):
    def __init__(self, program):
        super(EmulatedProgram, self).__init__(program)
        self.emuHelper = EmulatorHelper(program)
        self.wasmHelper = WasmEmulationHelper(self.emuHelper.language)
        self.analysis = WasmAnalysis.getState(program)

        ramSpace = self.currentProgram.addressFactory.defaultAddressSpace
        self.retAddr = ramSpace.getAddress(ret_addr)
        self.nullAddr = ramSpace.getAddress(null_val)
        self.emuHelper.setBreakpoint(self.retAddr)
        self.emuHelper.setBreakpoint(self.nullAddr)

    def run_function(self, function, args):
        stackBase = self.emuHelper.language.getRegister("s0").address
        memState = self.emuHelper.emulator.memState

        if len(args) != len(function.signature.arguments):
            raise Exception("wrong number of arguments: got %d, expected %d" % (len(args), len(function.signature.arguments)))

        biArgs = [BigInteger(1, encode_arg(arg)[::-1]) for arg in args]
        self.wasmHelper.simulateCall(self.emuHelper.emulator, ret_addr, function.entryPoint.offset, biArgs)

        while 1:
            if not self.emuHelper.run(self.monitor):
                err = self.emuHelper.lastError
                if err.startswith("Unimplemented CALLOTHER pcodeop (halt_trap)"):
                    raise EmulationError("unreachable")
                elif err in ("Divide by 0", "Remainder by 0"):
                    raise EmulationError("integer divide by zero")
                raise EmulationError("Emulation stopped: " + err)
            if self.emuHelper.executionAddress == self.retAddr:
                break
            elif self.emuHelper.executionAddress == self.nullAddr:
                # tried to execute a null pointer
                raise EmulationError("uninitialized element")

        # Ghidra itself doesn't support multiple return values, so we grab that information from the Wasm analysis instead
        sig = self.analysis.getFunctionByAddress(function.entryPoint)
        res = []
        for i, rt in enumerate(sig.returns):
            res.append(self.emuHelper.readMemory(stackBase.add(i * WasmLoader.REG_SIZE), rt.size))
        return res

def import_program(dirname, filename):
    prog = importFile(File(os.path.join(dirname, filename)))
    if prog is None:
        raise Exception("Failed to import file!")

    tx = prog.startTransaction("analysis")
    mgr = AutoAnalysisManager.getAnalysisManager(prog)

    # Disable C stack analysis for wast tests
    options = prog.getOptions(Program.ANALYSIS_PROPERTIES)
    options.setInt("Wasm Pre-Analyzer.C Stack Pointer", -1)
    mgr.initializeOptions(options)

    mgr.reAnalyzeAll(None)
    mgr.waitForAnalysis(None, monitor)
    prog.endTransaction(tx, True)

    prog_api = EmulatedProgram(prog)
    return prog_api

def execute_action(progs, action):
    modname = action.get("module", None)
    prog = progs.get(modname, None)
    if prog is None:
        raise ValueError("module was not loaded")

    atype = action["type"]
    field = action["field"]
    export_ns = prog.getNamespace(None, "export")
    syms = prog.getSymbols(field, export_ns)
    if not syms:
        raise ValueError("exported name %s not found" % (field.encode("unicode_escape"),))
    sym_addr = syms[0].address

    if atype == "get":
        dlen = prog.getDataAt(sym_addr).length
        return [prog.emuHelper.readMemory(sym_addr, dlen)]
    elif atype == "invoke":
        func = prog.getFunctionAt(sym_addr)
        if func is None:
            raise ValueError("exported symbol %s is not a function" % (field.encode("unicode_escape"),))
        return prog.run_function(func, action["args"])
    else:
        raise ValueError("action type %s is not known" % (atype,))

def assert_equal(msg, res, exp):
    if res != exp:
        raise AssertionError("wrong %s: got %s, expected %s" % (msg, res, exp))

def format_f32(v):
    return "0x%08x (%s)" % (v, struct.unpack("<f", struct.pack("<I", v))[0])

def format_f64(v):
    return "0x%016x (%s)" % (v, struct.unpack("<d", struct.pack("<Q", v))[0])

def compare_f32(name, riv, eiv):
    if eiv == "nan:canonical":
        if (riv & 0x7fffffff) != 0x7fc00000:
            raise AssertionError("wrong %s: got %s, expected canonical nan" % (name, format_f32(riv)))
    elif eiv == "nan:arithmetic":
        if (riv & 0x7fc00000) != 0x7fc00000:
            raise AssertionError("wrong %s: got %s, expected arithmetic nan" % (name, format_f32(riv)))
    else:
        if riv != int(eiv):
            raise AssertionError("wrong %s: got %s, expected %s" % (name, format_f32(riv), format_f32(int(eiv))))

def compare_f64(name, riv, eiv):
    if eiv == "nan:canonical":
        if (riv & 0x7fffffffffffffff) != 0x7ff8000000000000:
            raise AssertionError("wrong %s: got %s, expected canonical nan" % (name, format_f64(riv)))
    elif eiv == "nan:arithmetic":
        if (riv & 0x7ff8000000000000) != 0x7ff8000000000000:
            raise AssertionError("wrong %s: got %s, expected arithmetic nan" % (name, format_f64(riv)))
    else:
        if riv != int(eiv):
            raise AssertionError("wrong %s: got %s, expected %s" % (name, format_f64(riv), format_f64(int(eiv))))

def compare_result_value(ei, ri):
    eit = ei["type"]
    eiv = ei["value"]
    if eit == "i32":
        assert_equal("i32 result length", len(ri), 4)
        riv, = struct.unpack("<I", ri)
        assert_equal("i32 result", riv, int(eiv))
    elif eit == "i64":
        assert_equal("i64 result length", len(ri), 8)
        riv, = struct.unpack("<Q", ri)
        assert_equal("i64 result", riv, int(eiv))
    elif eit == "f32":
        assert_equal("f32 result length", len(ri), 4)
        riv, = struct.unpack("<I", ri)
        compare_f32("f32 result", riv, eiv)
    elif eit == "f64":
        assert_equal("f64 result length", len(ri), 8)
        riv, = struct.unpack("<Q", ri)
        compare_f64("f64 result", riv, eiv)
    elif eit in ("externref", "funcref", "exnref"):
        assert_equal("ref result length", len(ri), 4)
        riv, = struct.unpack("<I", ri)
        assert_equal("ref result", riv, parse_ref(eit, eiv))
    elif eit == "v128":
        assert_equal("v128 result length", len(ri), 16)
        eilt = ei["lane_type"]
        if eilt == "i8":
            assert_equal("i8x16 result", struct.unpack("<16B", ri), tuple([int(c) for c in eiv]))
        elif eilt == "i16":
            assert_equal("i16x8 result", struct.unpack("<8H", ri), tuple([int(c) for c in eiv]))
        elif eilt == "i32":
            assert_equal("i32x4 result", struct.unpack("<4I", ri), tuple([int(c) for c in eiv]))
        elif eilt == "i64":
            assert_equal("i64x2 result", struct.unpack("<2Q", ri), tuple([int(c) for c in eiv]))
        elif eilt == "f32":
            riv = struct.unpack("<4I", ri)
            for i in range(4):
                compare_f32("f32x4 lane %d" % i, riv[i], eiv[i])
        elif eilt == "f64":
            riv = struct.unpack("<2Q", ri)
            for i in range(2):
                compare_f64("f64x2 lane %d" % i, riv[i], eiv[i])
        else:
            raise Exception("unknown lane type %s" % eilt)
    else:
        raise Exception("unknown value type %s" % eit)

def compare_result(result, expected):
    assert_equal("number of values returned", len(result), len(expected))

    for i in range(len(expected)):
        ri = result[i]
        ei = expected[i]
        compare_result_value(ei, ri)

def format_action(action):
    return "%s %s" % (action["type"], action["field"].encode("unicode_escape"))

def format_exception():
    etype, exc, tb = sys.exc_info()
    excs = unicode(exc)
    if excs:
        return "%s: %s" % (etype.__name__, excs)
    else:
        return etype.__name__

def main():
    file = askFile("wast .json file", "Open")
    json_fn = file.absolutePath

    testdata = json.load(open(json_fn))
    testdir = os.path.dirname(json_fn)
    # progs[None] is the current program
    progs = {None: None}

    succeeded_cmds = 0
    failed_cmds = 0
    skipped_cmds = 0

    wast_fn = testdata["source_filename"]
    for command in testdata["commands"]:
        prefix = "%s:%d:" % (wast_fn, command["line"])
        ctype = command["type"]
        if ctype == "module":
            try:
                prog = import_program(testdir, command["filename"])
                progs[None] = prog
                if "name" in command:
                    progs[command["name"]] = prog
                succeeded_cmds += 1
            except:
                eprint(prefix, "ERROR: failed to load module %s: %s" % (command["filename"], format_exception()))
                progs[None] = None
                failed_cmds += 1

        elif ctype == "action":
            try:
                execute_action(progs, command["action"])
                succeeded_cmds += 1
            except:
                eprint(prefix, "ERROR: failed to execute action %s: %s" % (format_action(command["action"]), format_exception()))
                failed_cmds += 1

        elif ctype == "assert_return":
            try:
                result = execute_action(progs, command["action"])
                compare_result(result, command["expected"])
                succeeded_cmds += 1
            except:
                eprint(prefix, "ERROR: assert_return %s failed: %s" % (format_action(command["action"]), format_exception()))
                failed_cmds += 1

        elif ctype == "assert_exhaustion":
            eprint(prefix, "NOTE: skipping assert_exhaustion %s" % format_action(command["action"]))
            skipped_cmds += 1

        elif ctype == "assert_trap":
            try:
                execute_action(progs, command["action"])
                eprint(prefix, "ERROR: assert_trap %s did not trap; expected %r" % (format_action(command["action"]), command["text"]))
                failed_cmds += 1
            except EmulationError as e:
                if e.args[0] == command["text"]:
                    succeeded_cmds += 1
                else:
                    eprint(prefix, "ERROR: assert_trap %s trapped with %r but expected %r" % (format_action(command["action"]), e.args[0], command["text"]))
                    failed_cmds += 1
            except:
                eprint(prefix, "ERROR: assert_trap %s failed: %s" % (format_action(command["action"]), format_exception()))
                failed_cmds += 1

        elif ctype == "assert_invalid":
            eprint(prefix, "NOTE: skipping assert_invalid %s" % (command["filename"],))
            skipped_cmds += 1

        elif ctype == "assert_malformed":
            eprint(prefix, "NOTE: skipping assert_malformed %s" % (command["filename"],))
            skipped_cmds += 1

        elif ctype == "assert_uninstantiable":
            eprint(prefix, "NOTE: skipping assert_uninstantiable %s" % (command["filename"],))
            skipped_cmds += 1

        elif ctype == "assert_unlinkable":
            eprint(prefix, "NOTE: skipping assert_unlinkable %s" % (command["filename"],))
            skipped_cmds += 1

        elif ctype == "register":
            # TODO: save program in the root folder to benefit from automatic linking
            progs[command["as"]] = progs[command.get("name", None)]
            succeeded_cmds += 1

        else:
            eprint(prefix, "ERROR: unrecognized command %s" % (command["type"],))
            failed_cmds += 1

    if succeeded_cmds + failed_cmds + skipped_cmds != len(testdata["commands"]):
        eprint("ERROR: invalid result totals!")

    eprint("SUMMARY: %s: %d succeeded, %d failed, %d skipped (%d total)" % (os.path.basename(json_fn), succeeded_cmds, failed_cmds, skipped_cmds, len(testdata["commands"])))

if __name__ == "__main__":
    main()
