#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <stdexcept>
#include <vector>

import openproof.client;
import openproof.credentials;
import openproof.foundation;
import openproof.gateway;
import openproof.security;
import openproof.telemetry;

namespace client = openproof::client;
namespace cred = openproof::credentials;
namespace fnd = openproof::foundation;
namespace gateway = openproof::gateway;
namespace security = openproof::security;
namespace telemetry = openproof::telemetry;

namespace openproof::fuzzing {
void resetCoverage() noexcept;
[[nodiscard]] std::span<const std::uint8_t> currentCoverage() noexcept;
}

namespace {

struct Options final {
    std::size_t runs{100'000U};
    std::size_t maxLength{4096U};
    std::filesystem::path corpus{OPENPROOF_FUZZ_DEFAULT_CORPUS};
    std::filesystem::path artifacts{"fuzz-artifacts"};
};

[[nodiscard]] bool parseSize(std::string_view value, std::size_t& destination)
{
    std::size_t parsed{};
    const auto result = std::from_chars(
        value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size()
        || parsed == 0U) return false;
    destination = parsed;
    return true;
}

[[nodiscard]] bool parseOptions(int argc, char** argv, Options& options)
{
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument{argv[index]};
        if (argument == "--runs" && index + 1 < argc) {
            if (!parseSize(argv[++index], options.runs)) return false;
        } else if (argument == "--max-len" && index + 1 < argc) {
            if (!parseSize(argv[++index], options.maxLength)
                || options.maxLength > 65'536U) return false;
        } else if (argument == "--corpus" && index + 1 < argc) {
            options.corpus = argv[++index];
        } else if (argument == "--artifacts" && index + 1 < argc) {
            options.artifacts = argv[++index];
        } else {
            return false;
        }
    }
    return options.runs <= 10'000'000U;
}

[[nodiscard]] std::vector<std::byte> readFile(
    const std::filesystem::path& path, std::size_t maximum)
{
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    if (error || size > maximum) return {};
    std::ifstream input{path, std::ios::binary};
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    input.read(reinterpret_cast<char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
    if (!input && !bytes.empty()) return {};
    return bytes;
}

void writeFile(const std::filesystem::path& path, std::span<const std::byte> bytes)
{
    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!output) throw std::runtime_error{"cannot persist fuzz artifact"};
}

[[nodiscard]] std::uint64_t hashInput(std::span<const std::byte> bytes) noexcept
{
    std::uint64_t hash = 1469598103934665603ULL;
    for (const std::byte value : bytes) {
        hash ^= std::to_integer<std::uint8_t>(value);
        hash *= 1099511628211ULL;
    }
    return hash;
}

void exercise(std::span<const std::byte> bytes)
{
    std::string input;
    if (!bytes.empty()) {
        input.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }
    static_cast<void>(gateway::parseHttpMethod(input));
    static_cast<void>(gateway::HttpRequest::create(
        gateway::HttpMethod::Get, input, {{"x-fuzz", input}}, input,
        "192.0.2.1", fnd::CorrelationId{"coverage-fuzz"}));
    static_cast<void>(cred::PasswordHash::parse(input));
    static_cast<void>(telemetry::TraceContext::parseTraceParent(input));
    static_cast<void>(client::RedirectUri::create(input, client::ClientKind::Web));
    static_cast<void>(client::RedirectUri::create(input, client::ClientKind::Native));
    static_cast<void>(security::validateRs256PublicKey(input));
    static_cast<void>(security::rsaJwkThumbprint(input, input));
    static_cast<void>(security::verifyRs256Jwk(input, input, input));
    static_cast<void>(fnd::fromHex(input));
    static_cast<void>(fnd::fromBase64Url(input));
}

void mutate(std::vector<std::byte>& value, std::mt19937_64& random,
            std::size_t maximum)
{
    std::uniform_int_distribution<unsigned int> operation{0U, 5U};
    std::uniform_int_distribution<unsigned int> octet{0U, 255U};
    const unsigned int mutations = 1U + static_cast<unsigned int>(random() % 8U);
    for (unsigned int attempt = 0; attempt < mutations; ++attempt) {
        const unsigned int selected = operation(random);
        if (selected == 0U && !value.empty()) {
            const auto index = static_cast<std::size_t>(random() % value.size());
            value[index] ^= std::byte{static_cast<std::uint8_t>(1U << (random() % 8U))};
        } else if (selected == 1U && !value.empty()) {
            value[static_cast<std::size_t>(random() % value.size())]
                = std::byte{static_cast<std::uint8_t>(octet(random))};
        } else if (selected == 2U && value.size() < maximum) {
            const auto index = value.empty() ? 0U
                : static_cast<std::size_t>(random() % (value.size() + 1U));
            value.insert(value.begin() + static_cast<std::ptrdiff_t>(index),
                         std::byte{static_cast<std::uint8_t>(octet(random))});
        } else if (selected == 3U && !value.empty()) {
            value.erase(value.begin() + static_cast<std::ptrdiff_t>(random() % value.size()));
        } else if (selected == 4U && value.size() + 4U <= maximum) {
            constexpr std::string_view dictionary[] = {
                "../", "%00", "Bearer ", "traceparent", "https://", "-----BEGIN", "{}", "//"};
            const auto word = dictionary[random() % std::size(dictionary)];
            const auto room = maximum - value.size();
            const auto count = std::min(room, word.size());
            const auto index = value.empty() ? 0U
                : static_cast<std::size_t>(random() % (value.size() + 1U));
            value.insert(value.begin() + static_cast<std::ptrdiff_t>(index),
                reinterpret_cast<const std::byte*>(word.data()),
                reinterpret_cast<const std::byte*>(word.data() + count));
        } else if (selected == 5U && value.size() > 1U) {
            value.resize(static_cast<std::size_t>(random() % value.size()));
        }
    }
}

} // namespace

int main(int argc, char** argv)
{
    Options options;
    if (!parseOptions(argc, argv, options)) {
        std::cerr << "usage: openproof_boundary_fuzzer [--runs N] [--max-len N] "
                     "[--corpus DIR] [--artifacts DIR]\n";
        return 2;
    }
    std::error_code error;
    std::filesystem::create_directories(options.artifacts, error);
    if (error) {
        std::cerr << "cannot create artifact directory\n";
        return 2;
    }
    const auto learnedCorpus = options.artifacts / "corpus";
    std::filesystem::create_directories(learnedCorpus, error);
    if (error) {
        std::cerr << "cannot create learned corpus directory\n";
        return 2;
    }

    std::vector<std::vector<std::byte>> queue;
    for (const auto& directory : {options.corpus, learnedCorpus}) {
        if (std::filesystem::is_directory(directory)) {
            for (const auto& entry : std::filesystem::directory_iterator(directory)) {
                if (entry.is_regular_file()) {
                    queue.push_back(readFile(entry.path(), options.maxLength));
                }
            }
        }
    }
    if (queue.empty()) queue.emplace_back();

    std::vector<std::uint8_t> seen(openproof::fuzzing::currentCoverage().size(), 0U);
    std::mt19937_64 random{0x4f70656e50726f6fULL};
    std::size_t discoveries{};
    for (std::size_t run = 0; run < options.runs; ++run) {
        std::vector<std::byte> candidate = queue[run % queue.size()];
        if (run >= queue.size()) mutate(candidate, random, options.maxLength);
        openproof::fuzzing::resetCoverage();
        try {
            exercise(candidate);
        } catch (...) {
            const auto artifact = options.artifacts
                / ("crash-" + std::to_string(hashInput(candidate)));
            writeFile(artifact, candidate);
            std::cerr << "uncaught exception; artifact=" << artifact << '\n';
            return 1;
        }
        bool novel = false;
        const auto coverage = openproof::fuzzing::currentCoverage();
        for (std::size_t index = 0; index < coverage.size(); ++index) {
            if (coverage[index] != 0U && seen[index] == 0U) {
                seen[index] = 1U;
                novel = true;
            }
        }
        if (novel && run >= queue.size()) {
            const auto learned = learnedCorpus
                / ("id-" + std::to_string(hashInput(candidate)));
            if (!std::filesystem::exists(learned)) writeFile(learned, candidate);
            queue.push_back(candidate);
            ++discoveries;
        }
    }
    const auto edges = static_cast<std::size_t>(
        std::ranges::count(seen, static_cast<std::uint8_t>(1U)));
    std::cout << "coverage fuzz passed: runs=" << options.runs
              << " corpus=" << queue.size() << " discoveries=" << discoveries
              << " features=" << edges << " learned=" << learnedCorpus << '\n';
    return 0;
}
