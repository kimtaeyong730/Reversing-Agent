"""angr solver for chall - run with: python angr_solve.py"""
import angr, claripy, sys

binary = r"C:\Users\taed\Downloads\940350bb-7e1e-4653-b50a-6252884c723d (1)\chall"
proj = angr.Project(binary, auto_load_libs=False)
base = proj.loader.main_object.mapped_base

flag = claripy.BVS("flag", 8*16)
state = proj.factory.blank_state(
    addr=base+0x1189,  # complex_function
    add_options={angr.options.LAZY_SOLVES}
)
buf = 0x700000
for i in range(16):
    state.memory.store(buf+i, flag.get_byte(i))
state.memory.store(buf+16, claripy.BVV(0, 8))
state.regs.rdi = buf
state.regs.rsp = 0x7fff0000
state.memory.store(0x7fff0000, claripy.BVV(0xdeadbeef, 64))

for i in range(16):
    b = flag.get_byte(i)
    state.solver.add(b >= 0x20)
    state.solver.add(b <= 0x7e)

simgr = proj.factory.simulation_manager(state)
print("Exploring complex_function...")
simgr.explore(find=base+0x1bfe9, avoid=base+0x1bfe2)

if simgr.found:
    result = simgr.found[0].solver.eval(flag, cast_to=bytes)
    print(f"FLAG: {result.decode()}")
else:
    print(f"Not found. active={len(simgr.active)} errored={len(simgr.errored)} avoided={len(simgr.avoid)}")
