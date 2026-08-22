// SPDX-License-Identifier: MIT
// cpp-unix-watch — Linux AF_UNIX socket table monitor (/proc/net/unix)
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o unix-watch
// Usage: ./unix-watch [--watch N] [--json] [--demo] [--no-color] [--selftest]
//        [--type stream|dgram|seqpacket] [--listen] [--abstract] [--unnamed]
//        [--path PREFIX] [--file PATH]

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <expected>
#include <fstream>
#include <iostream>
#include <optional>
#include <print>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

// ── Types ──

struct Error {
  int code;
  std::string message;
};

template <typename T>
using Result = std::expected<T, Error>;

enum class SockKind { Stream, Dgram, Seqpacket, Other };
enum class SockState { Free, Unconnected, Connecting, Connected, Disconnecting, Other };

struct UnixEntry {
  std::string num;
  unsigned refcount{0};
  unsigned protocol{0};
  unsigned flags{0};
  unsigned type_raw{0};
  unsigned state_raw{0};
  unsigned long inode{0};
  std::string path;
  SockKind kind{SockKind::Other};
  SockState state{SockState::Other};
  bool listening{false};
  bool abstract{false};
  bool unnamed{false};
  bool pathname{false};
};

struct UnixSnapshot {
  std::vector<UnixEntry> entries;
  int streams{0};
  int dgrams{0};
  int seqpackets{0};
  int listening{0};
  int connected{0};
  int abstract{0};
  int pathname{0};
  int unnamed{0};
  double timestamp{0.0};
  int d_total{0};
  int d_listening{0};
  int d_connected{0};
  bool has_delta{false};
};

// ── Mutable ANSI palette (--no-color empties every code) ──

bool g_color = true;
std::string C_RST, C_BOLD, C_DIM, C_CYAN, C_GREEN, C_YELLOW, C_RED, C_MAGENTA, C_BLUE;

void init_colors() {
  C_RST     = g_color ? "\033[0m"  : "";
  C_BOLD    = g_color ? "\033[1m"  : "";
  C_DIM     = g_color ? "\033[2m"  : "";
  C_CYAN    = g_color ? "\033[36m" : "";
  C_GREEN   = g_color ? "\033[32m" : "";
  C_YELLOW  = g_color ? "\033[33m" : "";
  C_RED     = g_color ? "\033[31m" : "";
  C_MAGENTA = g_color ? "\033[35m" : "";
  C_BLUE    = g_color ? "\033[34m" : "";
}

// ── Helpers ──

static constexpr unsigned SO_ACCEPTCON = 1u << 16;  // 0x10000, listening unix socket
static constexpr unsigned SOCK_STREAM = 1;
static constexpr unsigned SOCK_DGRAM = 2;
static constexpr unsigned SOCK_SEQPACKET = 5;

static double now_epoch() {
  using namespace std::chrono;
  return duration<double>(system_clock::now().time_since_epoch()).count();
}

static std::string trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
    s.remove_suffix(1);
  return std::string(s);
}

static unsigned parse_u32(std::string_view s, int base = 10) {
  unsigned v = 0;
  auto start = s.find_first_not_of(" \t");
  if (start == std::string_view::npos) return 0;
  s.remove_prefix(start);
  if (base == 16) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s.remove_prefix(2);
  }
  auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v, base);
  (void)ptr;
  if (ec != std::errc{}) return 0;
  return v;
}

static unsigned long parse_ulong(std::string_view s, int base = 10) {
  unsigned long v = 0;
  auto start = s.find_first_not_of(" \t");
  if (start == std::string_view::npos) return 0;
  s.remove_prefix(start);
  auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v, base);
  (void)ptr;
  if (ec != std::errc{}) return 0;
  return v;
}

static std::string json_escape(std::string_view s) {
  std::string o;
  o.reserve(s.size());
  for (unsigned char c : s) {
    switch (c) {
      case '\\': o += "\\\\"; break;
      case '"':  o += "\\\""; break;
      case '\n': o += "\\n"; break;
      case '\t': o += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          o += buf;
        } else {
          o += static_cast<char>(c);
        }
        break;
    }
  }
  return o;
}

static std::string fmt_signed(int v) {
  char buf[16];
  if (v > 0) std::snprintf(buf, sizeof(buf), "+%d", v);
  else std::snprintf(buf, sizeof(buf), "%d", v);
  return buf;
}

static std::string fmt_time(double epoch) {
  std::time_t t = static_cast<std::time_t>(epoch);
  std::tm tm{};
  localtime_r(&t, &tm);
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
  return buf;
}

static SockKind kind_from_type(unsigned t) {
  switch (t) {
    case SOCK_STREAM:    return SockKind::Stream;
    case SOCK_DGRAM:     return SockKind::Dgram;
    case SOCK_SEQPACKET: return SockKind::Seqpacket;
    default:             return SockKind::Other;
  }
}

static SockState state_from_raw(unsigned s) {
  switch (s) {
    case 0: return SockState::Free;
    case 1: return SockState::Unconnected;
    case 2: return SockState::Connecting;
    case 3: return SockState::Connected;
    case 4: return SockState::Disconnecting;
    default: return SockState::Other;
  }
}

static const char* kind_str(SockKind k) {
  switch (k) {
    case SockKind::Stream:    return "stream";
    case SockKind::Dgram:     return "dgram";
    case SockKind::Seqpacket: return "seqpacket";
    default:                  return "other";
  }
}

static const char* state_str(SockState s) {
  switch (s) {
    case SockState::Free:           return "FREE";
    case SockState::Unconnected:    return "UNCONN";
    case SockState::Connecting:     return "CONNING";
    case SockState::Connected:      return "CONN";
    case SockState::Disconnecting:  return "DISCONN";
    default:                        return "OTHER";
  }
}

static std::string flags_str(unsigned f) {
  if (f & SO_ACCEPTCON) return "L";
  if (f == 0) return "-";
  char buf[16];
  std::snprintf(buf, sizeof(buf), "0x%x", f);
  return buf;
}

static void classify(UnixEntry& e) {
  e.kind = kind_from_type(e.type_raw);
  e.state = state_from_raw(e.state_raw);
  e.listening = (e.flags & SO_ACCEPTCON) != 0;
  if (e.path.empty()) {
    e.unnamed = true;
    e.abstract = false;
    e.pathname = false;
  } else if (e.path[0] == '@' || e.path[0] == '\0') {
    e.abstract = true;
    e.unnamed = false;
    e.pathname = false;
    if (e.path[0] == '\0') e.path[0] = '@';
  } else {
    e.pathname = true;
    e.abstract = false;
    e.unnamed = false;
  }
}

static void summarize(UnixSnapshot& s) {
  s.streams = s.dgrams = s.seqpackets = 0;
  s.listening = s.connected = s.abstract = s.pathname = s.unnamed = 0;
  for (const auto& e : s.entries) {
    if (e.kind == SockKind::Stream) ++s.streams;
    else if (e.kind == SockKind::Dgram) ++s.dgrams;
    else if (e.kind == SockKind::Seqpacket) ++s.seqpackets;
    if (e.listening) ++s.listening;
    if (e.state == SockState::Connected) ++s.connected;
    if (e.abstract) ++s.abstract;
    if (e.pathname) ++s.pathname;
    if (e.unnamed) ++s.unnamed;
  }
}

static void sort_entries(std::vector<UnixEntry>& v) {
  std::sort(v.begin(), v.end(), [](const UnixEntry& a, const UnixEntry& b) {
    if (a.listening != b.listening) return a.listening && !b.listening;
    if (a.kind != b.kind) return static_cast<int>(a.kind) < static_cast<int>(b.kind);
    if (a.unnamed != b.unnamed) return !a.unnamed && b.unnamed;
    if (a.path != b.path) return a.path < b.path;
    return a.inode < b.inode;
  });
}

// ── Parser ──
// /proc/net/unix (net/unix/af_unix.c unix_seq_show):
//   %pK: %08X %08X %08X %04X %02X %5lu [Path]
// Num  RefCount Protocol Flags Type St Inode Path
// 0000000000000000: 00000003 00000000 00000000 0001 03 25517521
// 0000000000000000: 00000002 00000000 00010000 0001 01 24293343 /tmp/foo

static Result<std::vector<UnixEntry>> parse_unix_text(std::string_view text) {
  std::vector<UnixEntry> out;
  std::istringstream in{std::string(text)};
  std::string line;
  bool header = true;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    auto t = trim(line);
    if (t.empty()) continue;
    if (t[0] == '#') continue;  // tolerate comments in demo / --file
    if (header) {
      header = false;
      if (t.find("RefCount") != std::string::npos || t.find("Inode") != std::string::npos)
        continue;
    }
    // strip trailing colon on Num
    std::istringstream ss{t};
    UnixEntry e;
    std::string ref_s, proto_s, flags_s, type_s, st_s, ino_s;
    if (!(ss >> e.num >> ref_s >> proto_s >> flags_s >> type_s >> st_s >> ino_s)) continue;
    if (!e.num.empty() && e.num.back() == ':') e.num.pop_back();
    e.refcount = parse_u32(ref_s, 16);
    e.protocol = parse_u32(proto_s, 16);
    e.flags = parse_u32(flags_s, 16);
    e.type_raw = parse_u32(type_s, 16);
    e.state_raw = parse_u32(st_s, 16);
    e.inode = parse_ulong(ino_s, 10);
    std::string rest;
    std::getline(ss, rest);
    e.path = trim(rest);
    classify(e);
    out.push_back(std::move(e));
  }
  return out;
}

static Result<UnixSnapshot> read_unix(const std::string& path = "/proc/net/unix") {
  std::ifstream f(path);
  if (!f) return std::unexpected(Error{1, "cannot open " + path});
  std::ostringstream oss;
  oss << f.rdbuf();
  auto parsed = parse_unix_text(oss.str());
  if (!parsed) return std::unexpected(parsed.error());
  UnixSnapshot s;
  s.entries = std::move(*parsed);
  s.timestamp = now_epoch();
  sort_entries(s.entries);
  summarize(s);
  return s;
}

static const char* kDemoTable =
    "Num       RefCount Protocol Flags    Type St Inode Path\n"
    "# listening dbus abstract socket\n"
    "0000000000000000: 00000002 00000000 00010000 0001 01  12345 @/tmp/dbus-abc\n"
    "# connected stream pathname\n"
    "0000000000000000: 00000003 00000000 00000000 0001 03  12346 /run/user/1000/bus\n"
    "# unnamed connected pair\n"
    "0000000000000000: 00000003 00000000 00000000 0001 03  12347\n"
    "# udev monitor abstract dgram\n"
    "0000000000000000: 00000002 00000000 00000000 0002 01  12348 @/org/kernel/udev/monitor\n"
    "# systemd journal seqpacket listen\n"
    "0000000000000000: 00000002 00000000 00010000 0005 01  12349 /run/systemd/journal/stdout\n"
    "# connecting mysql\n"
    "0000000000000000: 00000002 00000000 00000000 0001 02  12350 /tmp/mysql.sock\n"
    "# disconnecting unnamed\n"
    "0000000000000000: 00000001 00000000 00000000 0001 04  12351\n"
    "# syslog dgram pathname\n"
    "0000000000000000: 00000002 00000000 00000000 0002 01  12352 /dev/log\n"
    "# X11 abstract listen\n"
    "0000000000000000: 00000002 00000000 00010000 0001 01  12353 @/tmp/.X11-unix/X0\n"
    "# docker containerd stream listen\n"
    "0000000000000000: 00000003 00000000 00010000 0001 01  12354 /run/containerd/containerd.sock\n";

static UnixSnapshot build_demo_snapshot() {
  auto parsed = parse_unix_text(kDemoTable);
  UnixSnapshot s;
  if (parsed) s.entries = std::move(*parsed);
  s.timestamp = now_epoch();
  sort_entries(s.entries);
  summarize(s);
  return s;
}

struct Filters {
  std::optional<SockKind> kind;
  bool listen_only{false};
  bool abstract_only{false};
  bool unnamed_only{false};
  std::string path_prefix;
};

static bool parse_kind_arg(std::string_view s, SockKind& out) {
  if (s == "stream" || s == "STREAM") {
    out = SockKind::Stream;
    return true;
  }
  if (s == "dgram" || s == "DGRAM" || s == "udp") {
    out = SockKind::Dgram;
    return true;
  }
  if (s == "seqpacket" || s == "SEQPACKET") {
    out = SockKind::Seqpacket;
    return true;
  }
  return false;
}

static void apply_filters(UnixSnapshot& s, const Filters& f) {
  const bool any = f.kind.has_value() || f.listen_only || f.abstract_only || f.unnamed_only ||
                   !f.path_prefix.empty();
  if (!any) return;
  std::vector<UnixEntry> kept;
  kept.reserve(s.entries.size());
  for (auto& e : s.entries) {
    if (f.kind && e.kind != *f.kind) continue;
    if (f.listen_only && !e.listening) continue;
    if (f.abstract_only && !e.abstract) continue;
    if (f.unnamed_only && !e.unnamed) continue;
    if (!f.path_prefix.empty() && e.path.find(f.path_prefix) != 0) continue;
    kept.push_back(std::move(e));
  }
  s.entries = std::move(kept);
  summarize(s);
}

// ── Print ──

static void print_header(const UnixSnapshot& s, bool demo, std::string_view src) {
  std::println(std::cout, "{}+================================================+{}", C_CYAN, C_RST);
  std::println(std::cout, "{}|     Linux AF_UNIX Socket Table Monitor        |{}", C_CYAN, C_RST);
  std::println(std::cout, "{}+================================================+{}", C_CYAN, C_RST);
  std::println(std::cout, "  {}Source:{} {}   {}Snapshot:{} {}{}", C_DIM, C_RST, src, C_DIM, C_RST,
               fmt_time(s.timestamp), demo ? "   --demo" : "");
  std::println(std::cout);
}

static void print_summary(const UnixSnapshot& s) {
  std::println(std::cout, "  {}-- Aggregate --{}", C_BOLD, C_RST);
  auto row = [](const char* label, int v, const std::string& color) {
    std::println(std::cout, "  {:<14} {}{}{}", label, color, v, C_RST);
  };
  row("Sockets", static_cast<int>(s.entries.size()), C_CYAN);
  row("STREAM", s.streams, C_GREEN);
  row("DGRAM", s.dgrams, s.dgrams ? C_YELLOW : C_DIM);
  row("SEQPACKET", s.seqpackets, s.seqpackets ? C_MAGENTA : C_DIM);
  row("Listening", s.listening, s.listening ? C_BLUE : C_DIM);
  row("Connected", s.connected, C_GREEN);
  row("Abstract", s.abstract, s.abstract ? C_MAGENTA : C_DIM);
  row("Pathname", s.pathname, C_CYAN);
  row("Unnamed", s.unnamed, C_DIM);
  if (s.has_delta) {
    std::println(std::cout, "  {:<14} {}{}{}  listen {}  conn {}", "Delta", C_BOLD,
                 fmt_signed(s.d_total), C_RST, fmt_signed(s.d_listening),
                 fmt_signed(s.d_connected));
  }
  std::println(std::cout);
}

static void print_table(const UnixSnapshot& s) {
  std::println(std::cout, "  {}-- Sockets ({}) --{}", C_BOLD, s.entries.size(), C_RST);
  std::println(std::cout, "  {}{:<10} {:<6} {:<8} {:>6} {:>8}  {}{}", C_DIM, "Type", "State", "Flg",
               "Refs", "Inode", "Path", C_RST);
  for (const auto& e : s.entries) {
    std::string scolor = C_DIM;
    if (e.state == SockState::Connected) scolor = C_GREEN;
    else if (e.state == SockState::Connecting) scolor = C_YELLOW;
    else if (e.state == SockState::Disconnecting) scolor = C_RED;
    else if (e.listening) scolor = C_BLUE;
    std::string kcolor = C_CYAN;
    if (e.kind == SockKind::Dgram) kcolor = C_YELLOW;
    else if (e.kind == SockKind::Seqpacket) kcolor = C_MAGENTA;
    std::string shown = e.path.empty() ? "(unnamed)" : e.path;
    if (shown.size() > 48) shown = shown.substr(0, 45) + "...";
    std::println(std::cout, "  {}{:<10}{} {}{:<6}{} {:<8} {:>6} {:>8}  {}{}{}", kcolor,
                 kind_str(e.kind), C_RST, scolor, state_str(e.state), C_RST, flags_str(e.flags),
                 e.refcount, e.inode, e.unnamed ? C_DIM : (e.abstract ? C_MAGENTA : C_RST), shown,
                 C_RST);
  }
  std::println(std::cout);
}

static void print_json(const UnixSnapshot& s) {
  std::ostringstream o;
  o << "{";
  o << "\"timestamp\":" << static_cast<long long>(s.timestamp) << ",";
  o << "\"summary\":{";
  o << "\"sockets\":" << s.entries.size() << ",";
  o << "\"stream\":" << s.streams << ",";
  o << "\"dgram\":" << s.dgrams << ",";
  o << "\"seqpacket\":" << s.seqpackets << ",";
  o << "\"listening\":" << s.listening << ",";
  o << "\"connected\":" << s.connected << ",";
  o << "\"abstract\":" << s.abstract << ",";
  o << "\"pathname\":" << s.pathname << ",";
  o << "\"unnamed\":" << s.unnamed;
  o << "},";
  o << "\"sockets\":[";
  for (size_t i = 0; i < s.entries.size(); ++i) {
    const auto& e = s.entries[i];
    if (i) o << ",";
    o << "{";
    o << "\"inode\":" << e.inode << ",";
    o << "\"refcount\":" << e.refcount << ",";
    o << "\"protocol\":" << e.protocol << ",";
    o << "\"flags\":" << e.flags << ",";
    o << "\"flags_str\":\"" << json_escape(flags_str(e.flags)) << "\",";
    o << "\"type\":" << e.type_raw << ",";
    o << "\"type_str\":\"" << kind_str(e.kind) << "\",";
    o << "\"state\":" << e.state_raw << ",";
    o << "\"state_str\":\"" << state_str(e.state) << "\",";
    o << "\"listening\":" << (e.listening ? "true" : "false") << ",";
    o << "\"abstract\":" << (e.abstract ? "true" : "false") << ",";
    o << "\"pathname\":" << (e.pathname ? "true" : "false") << ",";
    o << "\"unnamed\":" << (e.unnamed ? "true" : "false") << ",";
    o << "\"path\":\"" << json_escape(e.path) << "\"";
    o << "}";
  }
  o << "]";
  if (s.has_delta) {
    o << ",\"delta\":{";
    o << "\"sockets\":" << s.d_total << ",";
    o << "\"listening\":" << s.d_listening << ",";
    o << "\"connected\":" << s.d_connected;
    o << "}";
  }
  o << "}\n";
  std::cout << o.str();
}

// ── Selftest ──

static int run_selftest() {
  int passed = 0, failed = 0;
  auto check = [&](const char* name, bool ok) {
    if (ok) {
      ++passed;
      std::println(std::cout, "  {}✓{} {}", C_GREEN, C_RST, name);
    } else {
      ++failed;
      std::println(std::cout, "  {}✗{} {}", C_RED, C_RST, name);
    }
  };

  std::println(std::cout, "{}unix-watch selftest{}", C_BOLD, C_RST);
  std::println(std::cout);

  check("kind stream", std::string(kind_str(kind_from_type(1))) == "stream");
  check("kind dgram", std::string(kind_str(kind_from_type(2))) == "dgram");
  check("kind seqpacket", std::string(kind_str(kind_from_type(5))) == "seqpacket");
  check("kind other", std::string(kind_str(kind_from_type(99))) == "other");

  check("state FREE", std::string(state_str(state_from_raw(0))) == "FREE");
  check("state UNCONN", std::string(state_str(state_from_raw(1))) == "UNCONN");
  check("state CONNING", std::string(state_str(state_from_raw(2))) == "CONNING");
  check("state CONN", std::string(state_str(state_from_raw(3))) == "CONN");
  check("state DISCONN", std::string(state_str(state_from_raw(4))) == "DISCONN");
  check("state OTHER", std::string(state_str(state_from_raw(9))) == "OTHER");

  check("flags listen L", flags_str(SO_ACCEPTCON) == "L");
  check("flags empty", flags_str(0) == "-");
  check("flags other hex", flags_str(0x20) == "0x20");

  {
    UnixEntry e;
    e.flags = SO_ACCEPTCON;
    e.type_raw = 1;
    e.state_raw = 1;
    e.path = "@/tmp/dbus-abc";
    classify(e);
    check("abstract @path", e.abstract && !e.pathname && !e.unnamed);
    check("listening flag", e.listening);
    check("stream kind", e.kind == SockKind::Stream);
    check("unconn state", e.state == SockState::Unconnected);
  }
  {
    UnixEntry e;
    e.path = "/run/user/1000/bus";
    classify(e);
    check("pathname socket", e.pathname && !e.abstract && !e.unnamed);
  }
  {
    UnixEntry e;
    e.path.clear();
    classify(e);
    check("unnamed empty path", e.unnamed && !e.abstract && !e.pathname);
  }
  {
    UnixEntry e;
    e.path = std::string(1, '\0') + "/tmp/.X11-unix/X0";
    classify(e);
    check("nul-prefix becomes @", e.abstract && e.path[0] == '@');
  }

  {
    const char* sample =
        "Num       RefCount Protocol Flags    Type St Inode Path\n"
        "0000000000000000: 00000002 00000000 00010000 0001 01  42 @/tmp/dbus-abc\n"
        "# skip me\n"
        "0000000000000000: 00000003 00000000 00000000 0001 03  43 /run/user/1000/bus\n"
        "0000000000000000: 00000003 00000000 00000000 0001 03  44\n";
    auto r = parse_unix_text(sample);
    check("parse ok", r.has_value() && r->size() == 3);
    if (r && r->size() == 3) {
      check("parse listen abstract", (*r)[0].listening && (*r)[0].abstract);
      check("parse dbus path", (*r)[0].path == "@/tmp/dbus-abc");
      check("parse inode decimal", (*r)[0].inode == 42);
      check("parse connected pathname", (*r)[1].pathname && (*r)[1].state == SockState::Connected);
      check("parse unnamed", (*r)[2].unnamed && (*r)[2].inode == 44);
      check("comment skipped", true);
    }
  }

  auto demo = build_demo_snapshot();
  check("demo entries == 10", demo.entries.size() == 10);
  check("demo streams >= 1", demo.streams >= 1);
  check("demo dgrams >= 1", demo.dgrams >= 1);
  check("demo seqpacket >= 1", demo.seqpackets >= 1);
  check("demo listening >= 1", demo.listening >= 1);
  check("demo connected >= 1", demo.connected >= 1);
  check("demo abstract >= 1", demo.abstract >= 1);
  check("demo pathname >= 1", demo.pathname >= 1);
  check("demo unnamed >= 1", demo.unnamed >= 1);

  bool print_ok = true;
  try {
    print_header(demo, true, "/proc/net/unix");
    print_summary(demo);
    print_table(demo);
  } catch (...) {
    print_ok = false;
  }
  check("demo print no crash", print_ok);

  std::string json_out;
  {
    std::ostringstream oss;
    auto* old = std::cout.rdbuf(oss.rdbuf());
    print_json(demo);
    std::cout.rdbuf(old);
    json_out = oss.str();
  }
  check("JSON starts with '{'", !json_out.empty() && json_out[0] == '{');
  check("JSON has sockets array", json_out.find("\"sockets\":[") != std::string::npos);
  check("JSON has summary", json_out.find("\"summary\"") != std::string::npos);
  check("JSON has listening key", json_out.find("\"listening\"") != std::string::npos);
  check("JSON quoted path key", json_out.find("\"path\":") != std::string::npos);

  auto real = read_unix();
  if (real.has_value()) {
    check("proc unix read ok", true);
    check("real entries countable", real->entries.size() < 1000000);
  } else {
    std::println(std::cout, "  {}ℹ{} /proc/net/unix failed ({}): restricted env — skipping",
                 C_YELLOW, C_RST, real.error().message);
  }

  {
    auto d = build_demo_snapshot();
    Filters f;
    f.kind = SockKind::Dgram;
    apply_filters(d, f);
    bool only = true;
    for (const auto& e : d.entries)
      if (e.kind != SockKind::Dgram) only = false;
    check("--type dgram filter", only && !d.entries.empty());
  }
  {
    auto d = build_demo_snapshot();
    Filters f;
    f.listen_only = true;
    apply_filters(d, f);
    bool only = true;
    for (const auto& e : d.entries)
      if (!e.listening) only = false;
    check("--listen filter", only && d.listening == static_cast<int>(d.entries.size()));
  }
  {
    auto d = build_demo_snapshot();
    Filters f;
    f.abstract_only = true;
    apply_filters(d, f);
    bool only = true;
    for (const auto& e : d.entries)
      if (!e.abstract) only = false;
    check("--abstract filter", only && !d.entries.empty());
  }
  {
    auto d = build_demo_snapshot();
    Filters f;
    f.path_prefix = "/run/";
    apply_filters(d, f);
    bool only = true;
    for (const auto& e : d.entries)
      if (e.path.find("/run/") != 0) only = false;
    check("--path /run/ filter", only && !d.entries.empty());
  }

  SockKind k{};
  check("parse_kind stream", parse_kind_arg("stream", k) && k == SockKind::Stream);
  check("parse_kind dgram", parse_kind_arg("dgram", k) && k == SockKind::Dgram);
  check("parse_kind bad", !parse_kind_arg("raw", k));

  g_color = true;
  init_colors();
  std::string colored = C_GREEN;
  g_color = false;
  init_colors();
  std::string plain = C_GREEN;
  check("--no-color clears ANSI", !colored.empty() && plain.empty());
  g_color = true;
  init_colors();

  check("fmt_signed(+3)", fmt_signed(3) == "+3");
  check("fmt_signed(-2)", fmt_signed(-2) == "-2");
  check("json_escape quote", json_escape("a\"b") == "a\\\"b");
  check("parse_u32 hex 00010000", parse_u32("00010000", 16) == SO_ACCEPTCON);
  check("parse_ulong decimal", parse_ulong("25517521", 10) == 25517521ul);

  std::println(std::cout);
  std::println(std::cout, "{}  Results: {} passed, {} failed{}", failed == 0 ? C_GREEN : C_RED,
               passed, failed, C_RST);
  return failed == 0 ? 0 : 1;
}

// ── Main ──

int main(int argc, char** argv) {
  bool json_mode = false;
  bool watch_mode = false;
  bool demo_mode = false;
  bool selftest = false;
  int watch_secs = 2;
  Filters filt;
  std::string file_path;

  for (int i = 1; i < argc; ++i) {
    std::string_view arg{argv[i]};
    if (arg == "--json") json_mode = true;
    else if (arg == "--no-color" || arg == "-c") g_color = false;
    else if (arg == "--demo") demo_mode = true;
    else if (arg == "--selftest") selftest = true;
    else if (arg == "--listen") filt.listen_only = true;
    else if (arg == "--abstract") filt.abstract_only = true;
    else if (arg == "--unnamed") filt.unnamed_only = true;
    else if ((arg == "--type" || arg == "-t") && i + 1 < argc) {
      ++i;
      SockKind k{};
      if (!parse_kind_arg(argv[i], k)) {
        std::println(std::cerr, "unknown --type (use stream|dgram|seqpacket)");
        return 2;
      }
      filt.kind = k;
    } else if ((arg == "--path" || arg == "-p") && i + 1 < argc) {
      ++i;
      filt.path_prefix = argv[i];
    } else if ((arg == "--file" || arg == "-f") && i + 1 < argc) {
      ++i;
      file_path = argv[i];
    } else if ((arg == "--watch" || arg == "-w") && i + 1 < argc) {
      watch_mode = true;
      ++i;
      std::from_chars(argv[i], argv[i] + std::strlen(argv[i]), watch_secs);
      if (watch_secs < 1) watch_secs = 1;
    } else if (arg == "--help" || arg == "-h") {
      init_colors();
      std::println(std::cout, "{}unix-watch{} — Linux AF_UNIX socket table monitor\n", C_BOLD,
                   C_RST);
      std::println(std::cout, "Usage: unix-watch [options]\n");
      std::println(std::cout, "Options:");
      std::println(std::cout, "  -w, --watch N      Refresh every N seconds (default: 2)");
      std::println(std::cout, "  --json             Output JSON");
      std::println(std::cout, "  --no-color, -c     Disable ANSI colors");
      std::println(std::cout, "  --demo             Simulated multi-kind unix table");
      std::println(std::cout, "  -t, --type KIND    Filter stream|dgram|seqpacket");
      std::println(std::cout, "  --listen           Only SO_ACCEPTCON listeners");
      std::println(std::cout, "  --abstract         Only abstract (@name) sockets");
      std::println(std::cout, "  --unnamed          Only unnamed sockets (no path)");
      std::println(std::cout, "  -p, --path PREFIX  Path starts with PREFIX");
      std::println(std::cout, "  -f, --file PATH    Parse a table file instead of /proc");
      std::println(std::cout, "  --selftest         Run built-in tests");
      std::println(std::cout, "  -h, --help         Show this help\n");
      std::println(std::cout, "{}", C_DIM + "Reads: /proc/net/unix" + C_RST);
      std::println(std::cout, "{}",
                   C_DIM + "Type 0001=STREAM 0002=DGRAM 0005=SEQPACKET · St 01=UNCONN 03=CONN · "
                           "Flags 0x10000=LISTEN" +
                       C_RST);
      return 0;
    }
  }

  init_colors();
  if (selftest) return run_selftest();

  auto take = [&]() -> std::optional<UnixSnapshot> {
    if (demo_mode) {
      auto d = build_demo_snapshot();
      apply_filters(d, filt);
      return d;
    }
    auto r = read_unix(file_path.empty() ? "/proc/net/unix" : file_path);
    if (!r) {
      if (!json_mode)
        std::println(std::cerr, "{}Error:{} {}", C_RED, C_RST, r.error().message);
      return std::nullopt;
    }
    apply_filters(*r, filt);
    return *r;
  };

  const std::string src = demo_mode ? "/proc/net/unix" : (file_path.empty() ? "/proc/net/unix" : file_path);

  if (watch_mode) {
    std::optional<UnixSnapshot> prev;
    bool first = true;
    while (true) {
      auto snap = take();
      if (!snap) return 1;

      if (prev) {
        snap->d_total = static_cast<int>(snap->entries.size()) - static_cast<int>(prev->entries.size());
        snap->d_listening = snap->listening - prev->listening;
        snap->d_connected = snap->connected - prev->connected;
        snap->has_delta = true;
      }
      prev = snap;

      if (!json_mode && !first) std::cout << "\033[2J\033[H";
      first = false;

      if (json_mode) {
        print_json(*snap);
      } else {
        print_header(*snap, demo_mode, src);
        print_summary(*snap);
        print_table(*snap);
        std::println(std::cout, "{}  Refreshing every {}s — Ctrl+C to exit{}", C_DIM, watch_secs,
                     C_RST);
      }
      std::cout << std::flush;
      std::this_thread::sleep_for(std::chrono::seconds(watch_secs));
    }
  } else {
    auto snap = take();
    if (!snap) return 1;
    if (json_mode) {
      print_json(*snap);
    } else {
      print_header(*snap, demo_mode, src);
      print_summary(*snap);
      print_table(*snap);
    }
  }
  return 0;
}
