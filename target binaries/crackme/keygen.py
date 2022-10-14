import angr

def main():
	SERIAL_SIZE = 19

	project = angr.Project ('crackme01_x64.exe')

	state = project.factory.blank_state(addr = 0x140001000)

	state.regs.rcx = serial_address = 0x100000
	state.regs.rdx = SERIAL_SIZE

	for i in xrange(0, SERIAL_SIZE):

		if i != 4 and i != 9 and i != 14:
			cond_numeric_f = state.memory.load(serial_address + i, 1) >= ord('0')
			cond_numeric_t = state.memory.load(serial_address + i, 1) <= ord('9')

			cond_alpha_lc_f = state.memory.load(serial_address + i, 1) >= ord('a')
			cond_alpha_lc_t = state.memory.load(serial_address + i, 1) <= ord('z')

			cond_alpha_uc_f = state.memory.load(serial_address + i, 1) >= ord('A')
			cond_alpha_uc_t = state.memory.load(serial_address + i, 1) <= ord('Z')

			state.add_constraints(
				state.se.Or(
					state.se.And(cond_numeric_f, cond_numeric_t),
					state.se.And(cond_alpha_lc_f, cond_alpha_lc_t),
					state.se.And(cond_alpha_uc_f, cond_alpha_uc_t)
				)
			)
		else:
			state.add_constraints(state.memory.load(serial_address + i, 1) == ord('-'))


	path_group = project.factory.path_group(state)

	result = path_group.explore (
		find = 0x1400010ee,
		avoid = [0x14000100c, 0x1400010fd]
	)

	if result.found:
		solution = path_group.found[0].state

		return solution.se.any_str(solution.memory.load(serial_address, SERIAL_SIZE))
	else:
		return 'Not found :('

if __name__ == "__main__":
    print main()
