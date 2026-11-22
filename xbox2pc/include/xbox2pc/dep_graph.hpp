#pragma once
// xbox2pc/dep_graph.hpp — directed DLL dependency graph (M2).
//
// Nodes are DLLs (plus one root node for the analyzed file itself).
// Edges carry function-level records (which functions/ordinals the source
// imports from the target, delay-load flag).
//
// Capabilities:
//   - cycle detection (DFS with coloring; reports each cycle once)
//   - missing dependency detection (edges whose target DLL is not provided)
//   - JSON export (nodes/edges/cycles/missing) via json_writer
//
// Construction modes:
//   - `from_report`: the analyzed file + its direct dependencies (single hop)
//   - `add_dependencies`: extend with second-level dependencies computed by
//     the caller (e.g. analyzing each imported DLL file when available).
//   - `from_images`: build a multi-module graph from several parsed images
//     (used for transitive/circular tests).
//
// The graph is deliberately insert-only; nothing mutates the parsed images.

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "xbox2pc/api_registry.hpp"
#include "xbox2pc/dep_analyzer.hpp"
#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/json_writer.hpp"
#include "xbox2pc/pe_parser.hpp"

namespace xbox2pc::graph {

// Function-level dependency record carried on an edge.
struct EdgeFunction {
    std::string name;
    std::uint32_t ordinal = 0;
    bool by_ordinal = false;
    bool delay_load = false;
};

// One directed edge: `from` depends on `to`.
struct GraphEdge {
    std::string from;            // node id (DLL name / root file name)
    std::string to;
    std::vector<EdgeFunction> functions;
    bool delay_load = false;     // at least one delay-load import on this edge
};

// A node: a DLL or the analyzed root file.
struct GraphNode {
    std::string id;              // canonical display name (as first seen)
    bool is_root = false;        // the analyzed file
    bool missing = false;        // not provided by any input image
    bool on_search_fail = false; // provided but its own analysis failed
    registry::ApiCategory category = registry::ApiCategory::Unknown;
    std::string category_name = "Unknown";
    bool classified = false;
};

// Detected cycle: the node sequence, e.g. {a.dll, b.dll, a.dll}.
struct Cycle {
    std::vector<std::string> nodes;
};

class DependencyGraph {
public:
    // Node id normalization: case-insensitive module naming.
    static std::string normalize_id(const std::string& name);

    // ── construction ──
    // Register a node; returns its normalized id. Second registration of the
    // same module merges (keeps the first spelling, updates flags).
    void add_node(const std::string& name, bool is_root = false);

    // Mark a node missing (referenced but not provided).
    void mark_missing(const std::string& name);

    // Add an edge with function records; nodes auto-registered.
    void add_edge(const std::string& from, const std::string& to,
                  std::vector<EdgeFunction> functions, bool delay_load);

    // Build the single-hop graph from one report: root -> each dependency.
    void build_from_report(const deps::DependencyReport& rep,
                           const pe::PeImage& root_image, diag::Diagnostics& diags);

    // Extend with a parsed dependency image: edges from that DLL to its own
    // imports (second level). Skips delay imports for clarity? No — includes
    // them, flagged.
    void add_dependencies(const deps::DependencyReport& rep, const pe::PeImage& img,
                          diag::Diagnostics& diags);

    // Convenience: build root graph plus one level for every provided
    // dependency image. `images` = (dll_name -> parsed image) pairs.
    void build_multi(const deps::DependencyReport& root_report, const pe::PeImage& root,
                     const std::vector<std::pair<std::string, pe::PeImage>>& deps_images,
                     diag::Diagnostics& diags);

    // ── queries ──
    // Simple cycles: each reported once, canonical rotation starting at the
    // lexicographically smallest node.
    std::vector<Cycle> detect_cycles() const;

    // Edges whose target node is missing.
    std::vector<GraphEdge> missing_dependencies() const;

    // Direct dependencies of a node (targets of outgoing edges).
    std::vector<std::string> dependencies_of(const std::string& node) const;

    // Transitive closure (BFS over edges), not including the start node.
    std::vector<std::string> transitive_dependencies(const std::string& node) const;

    // ── serialization ──
    json::Json to_json() const;

    // ── access ──
    const std::map<std::string, GraphNode>& nodes() const { return nodes_; }
    const std::vector<GraphEdge>& edges() const { return edges_; }
    std::size_t node_count() const { return nodes_.size(); }
    std::size_t edge_count() const { return edges_.size(); }

private:
    std::string canon(const std::string& name) const;

    std::map<std::string, GraphNode> nodes_;   // key = normalized id
    std::vector<GraphEdge> edges_;
};

}  // namespace xbox2pc::graph
