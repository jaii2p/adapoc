// C3 probe — VPK::open on truncated/malformed files. Real apps that don't
// expect exceptions from open() die on the throw; this harness catches and
// classifies so the sweep can tally behavior instead of aborting per run.
#include <cstdio>
#include <exception>
#include <iostream>

#include <vpkpp/format/VPK.h>

using namespace vpkpp;

int main(int argc, char** argv) {
	const auto path = argc > 1 ? argv[1] : "";
	try {
		auto packFile = VPK::open(path);
		if (!packFile) { std::printf("NULLPTR\n"); return 1; }
		std::printf("OPEN_OK\n");
		return 0;
	} catch (const std::exception& e) {
		std::printf("THREW: %s\n", e.what());
		return 3;
	} catch (...) {
		std::printf("THREW: (non-standard)\n");
		return 3;
	}
}