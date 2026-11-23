// xbox2pc/src/compat_report.cpp — M7 compatibility reporting.
//
// Given a parsed PE image + the M2 DependencyReport + the M6/M7 import
// metadata, produce a per-import compatibility verdict with stable codes,
// evidence citations, and honest statuses. The report NEVER claims a game
// is compatible merely because imports were recognized (explicit note).

#include "xbox2pc/compat_report.hpp"

#include <algorithm>

namespace xbox2pc::rt::api {

const char* compat_code_to_name(CompatCode c) {
    switch (c) {
        case CompatCode::OkImplemented: return "ok-implemented";
        case CompatCode::OkStubbed: return "ok-stubbed";
        case CompatCode::OkNative: return "ok-native";
        case CompatCode::Partial: return "partial";
        case CompatCode::StubMissing: return "stub-missing";
        case CompatCode::UnsupportedApi: return "unsupported-api";
        case CompatCode::UnsupportedModule: return "unsupported-module";
        case CompatCode::UnknownImport: return "unknown-import";
        case CompatCode::UnresolvedDelay: return "unresolved-delay";
        case CompatCode::InvalidImport: return "invalid-import";
        case CompatCode::MissingService: return "missing-service";
    }
    return "?";
}

CompatReport build_compat_report(const pe::PeImage& img,
                                const deps::DependencyReport& dep,
                                ApiRegistry& reg,
                                const DelayLoadReport* delay) {
    CompatReport rep;
    rep.source = dep.source.empty() ? img.source_name : dep.source;

    // ── regular imports ──
    for (const auto& edge : dep.dependencies) {
        const bool module_known = reg.find(edge.dll_name, "") != nullptr ||
                                  [&] {
                                      // Any descriptor for the module?
                                      for (const auto* d : reg.all()) {
                                          if (registry::normalize_module_name(
                                                  d->library) ==
                                              registry::normalize_module_name(
                                                  edge.dll_name)) {
                                              return true;
                                          }
                                      }
                                      return false;
                                  }();
        for (const auto& f : edge.functions) {
            ImportCompat row;
            row.dll = edge.dll_name;
            row.name = f.name;
            row.ordinal = f.ordinal;
            row.by_ordinal = f.by_ordinal;
            row.delay_load = f.delay_load;
            const ApiDescriptor* d =
                f.by_ordinal ? reg.find_ordinal(edge.dll_name, f.ordinal)
                             : reg.find(edge.dll_name, f.name);
            if (d != nullptr) {
                row.verified = true;
                row.evidence = d->evidence + " " + d->evidence_url;
                row.signature = d->signature;
                row.compat = d->compat;
                const bool has_impl = reg.has_implementation(row.dll, row.name);
                if (has_impl) {
                    switch (d->compat) {
                        case ApiStatus::NativeEquivalent:
                            row.code = CompatCode::OkNative; break;
                        case ApiStatus::FullyImplemented:
                            row.code = CompatCode::OkImplemented; break;
                        case ApiStatus::PartiallyImplemented:
                            row.code = CompatCode::Partial; break;
                        case ApiStatus::Stubbed:
                            row.code = CompatCode::OkStubbed; break;
                        default: row.code = CompatCode::StubMissing; break;
                    }
                } else {
                    row.code = CompatCode::StubMissing;
                    row.note = "verified descriptor, no implementation "
                               "registered (service down or not loaded)";
                }
            } else if (module_known) {
                row.code = f.unresolved ? CompatCode::InvalidImport
                                        : CompatCode::UnsupportedApi;
                row.note = f.unresolved
                               ? "parser could not resolve the thunk"
                               : "module partially known; this export has no "
                                 "verified descriptor (never guessed)";
            } else {
                row.code = f.by_ordinal ? CompatCode::UnknownImport
                                        : CompatCode::UnknownImport;
                row.note = "no evidence for this module in the "
                           "compatibility runtime (missing library)";
            }
            rep.rows.push_back(std::move(row));
        }
    }

    // ── delay-load imports ──
    if (delay != nullptr) {
        for (const auto& u : delay->failures) {
            ImportCompat row;
            row.dll = u.dll;
            row.name = u.name;
            row.delay_load = true;
            row.code = CompatCode::UnresolvedDelay;
            row.note = u.note;
            rep.rows.push_back(std::move(row));
        }
        rep.delay_entries = delay->entries;
        rep.delay_resolved = delay->resolved;
    }

    // ── summary counters ──
    for (const auto& r : rep.rows) ++rep.counts[static_cast<std::size_t>(r.code)];
    rep.verdict = rep.rows.empty() ? "no imports (nothing to judge)"
                  : rep.counts[static_cast<std::size_t>(CompatCode::OkImplemented)] +
                            rep.counts[static_cast<std::size_t>(CompatCode::OkStubbed)] +
                            rep.counts[static_cast<std::size_t>(CompatCode::OkNative)] ==
                        rep.rows.size()
                        ? "ALL imports covered (still NOT a compatibility claim)"
                        : "imports partially covered (see codes)";
    return rep;
}

}  // namespace xbox2pc::rt::api
