// xbox2pc/dep_graph.cpp — directed dependency graph implementation.

#include "xbox2pc/dep_graph.hpp"

#include <algorithm>
#include <deque>
#include <set>
#include <utility>

namespace xbox2pc::graph {

namespace {
// Reuse the registry normalization so graph node ids match classifier keys.
std::string norm(const std::string& s) { return registry::normalize_module_name(s); }
}  // namespace

std::string DependencyGraph::normalize_id(const std::string& name) {
    return registry::normalize_module_name(name);
}

std::string DependencyGraph::canon(const std::string& name) const {
    return norm(name);
}

void DependencyGraph::add_node(const std::string& name, bool is_root) {
    const std::string id = norm(name);
    auto it = nodes_.find(id);
    if (it == nodes_.end()) {
        GraphNode n;
        n.id = name;  // keep first-seen display spelling
        n.is_root = is_root;
        nodes_.emplace(id, std::move(n));
        return;
    }
    // Merge: root flag wins if any registration says root.
    if (is_root) it->second.is_root = true;
    // A later real registration clears "missing" (the DLL was provided).
    it->second.missing = false;
}

void DependencyGraph::mark_missing(const std::string& name) {
    const std::string id = norm(name);
    auto it = nodes_.find(id);
    if (it == nodes_.end()) {
        GraphNode n;
        n.id = name;
        n.missing = true;
        nodes_.emplace(id, std::move(n));
    } else if (!it->second.is_root) {
        it->second.missing = true;
    }
}

void DependencyGraph::add_edge(const std::string& from, const std::string& to,
                               std::vector<EdgeFunction> functions, bool delay_load) {
    add_node(from, false);
    add_node(to, false);
    // Merge parallel edges (same from/to) by appending functions.
    for (auto& e : edges_) {
        if (norm(e.from) == norm(from) && norm(e.to) == norm(to)) {
            for (auto& f : functions) e.functions.push_back(f);
            if (delay_load) e.delay_load = true;
            return;
        }
    }
    GraphEdge e;
    e.from = from;
    e.to = to;
    e.functions = std::move(functions);
    e.delay_load = delay_load;
    edges_.push_back(std::move(e));
}

void DependencyGraph::build_from_report(const deps::DependencyReport& rep,
                                        const pe::PeImage& root_image,
                                        diag::Diagnostics& diags) {
    // Root node: the analyzed file itself.
    const std::string root_name = root_image.source_name;
    add_node(root_name, true);
    if (root_name.empty()) {
        diags.warning("root image has no source name; root node named '<root>'");
    }

    const registry::ApiRegistry reg;
    for (const auto& d : rep.dependencies) {
        add_node(d.dll_name, false);
        std::vector<EdgeFunction> fns;
        fns.reserve(d.functions.size());
        for (const auto& f : d.functions) {
            EdgeFunction ef;
            ef.name = f.name;
            ef.ordinal = f.ordinal;
            ef.by_ordinal = f.by_ordinal;
            ef.delay_load = f.delay_load;
            fns.push_back(std::move(ef));
        }
        add_edge(root_name, d.dll_name, std::move(fns), d.delay_import);

        // Classification on the node.
        const std::string id = norm(d.dll_name);
        if (auto rec = reg.classify_library(d.dll_name)) {
            nodes_[id].category = rec->category;
            nodes_[id].category_name = registry::category_to_name(rec->category);
            nodes_[id].classified = true;
        }
    }
}

// `diags` is part of the signature for symmetry with build_from_report;
// adding second-level edges has nothing to report.
void DependencyGraph::add_dependencies(const deps::DependencyReport& rep,
                                        const pe::PeImage& img, diag::Diagnostics& /*diags*/) {
    // The image IS the dll named img.source_name (caller passes parsed deps).
    add_node(img.source_name, false);
    for (const auto& d : rep.dependencies) {
        std::vector<EdgeFunction> fns;
        for (const auto& f : d.functions) {
            EdgeFunction ef;
            ef.name = f.name;
            ef.ordinal = f.ordinal;
            ef.by_ordinal = f.by_ordinal;
            ef.delay_load = f.delay_load;
            fns.push_back(std::move(ef));
        }
        add_edge(img.source_name, d.dll_name, std::move(fns), d.delay_import);
    }
}

void DependencyGraph::build_multi(const deps::DependencyReport& root_report,
                                  const pe::PeImage& root,
                                  const std::vector<std::pair<std::string, pe::PeImage>>& deps_images,
                                  diag::Diagnostics& diags) {
    build_from_report(root_report, root, diags);
    for (const auto& [name, img] : deps_images) {
        diag::Diagnostics sub;
        const auto rep = deps::analyze(img, sub);
        add_dependencies(rep, img, diags);
    }
}

// ── cycle detection ───────────────────────────────────────────────────────
//
// Iterative DFS with white/gray/black coloring. A back edge to a gray node
// closes a cycle; the cycle is the stack segment from that node to the top.

std::vector<Cycle> DependencyGraph::detect_cycles() const {
    // Adjacency over normalized ids.
    std::map<std::string, std::vector<std::string>> adj;
    for (const auto& e : edges_) adj[norm(e.from)].push_back(norm(e.to));
    for (auto& kv : adj) {
        std::sort(kv.second.begin(), kv.second.end());
        kv.second.erase(std::unique(kv.second.begin(), kv.second.end()), kv.second.end());
    }

    enum class Color { White, Gray, Black };
    std::map<std::string, Color> color;
    for (const auto& kv : nodes_) color.emplace(kv.first, Color::White);

    std::vector<Cycle> cycles;
    std::set<std::vector<std::string>> seen;
    std::vector<std::string> stack;
    std::map<std::string, std::size_t> pos;  // stack position of each node

    // Recursive lambda -> explicit stack of (node, next-child-index).
    struct Frame {
        std::string node;
        std::size_t next = 0;
    };
    std::vector<Frame> frames;

    auto push_frame = [&](const std::string& start) {
        color[start] = Color::Gray;
        stack.push_back(start);
        pos[start] = stack.size() - 1;
        frames.push_back(Frame{start, 0});
    };

    for (const auto& kv : nodes_) {
        if (color[kv.first] != Color::White) continue;
        push_frame(kv.first);
        while (!frames.empty()) {
            Frame& cur = frames.back();
            const auto it = adj.find(cur.node);
            const std::vector<std::string>& children =
                it == adj.end() ? std::vector<std::string>() : it->second;
            if (cur.next < children.size()) {
                const std::string child = children[cur.next++];
                if (color.count(child) == 0) continue;  // unknown target node
                if (color[child] == Color::White) {
                    push_frame(child);
                } else if (color[child] == Color::Gray) {
                    // Cycle: stack segment pos[child]..end (+child to close).
                    std::vector<std::string> cyc(stack.begin() + static_cast<std::ptrdiff_t>(pos[child]),
                                                 stack.end());
                    cyc.push_back(child);
                    // Canonical rotation: start at lexicographically smallest.
                    if (cyc.size() > 2) {
                        std::size_t min_i = 0;
                        for (std::size_t i = 1; i + 1 < cyc.size(); ++i) {
                            if (cyc[i] < cyc[min_i]) min_i = i;
                        }
                        std::vector<std::string> rotated;
                        // Duplicate the loop body so rotation covers all nodes.
                        for (std::size_t k = 0; k + 1 < cyc.size(); ++k) {
                            rotated.push_back(cyc[(min_i + k) % (cyc.size() - 1)]);
                        }
                        rotated.push_back(rotated[0]);
                        cyc = std::move(rotated);
                    }
                    if (seen.insert(cyc).second) cycles.push_back(Cycle{cyc});
                }
                // Black: already finished, ignore.
            } else {
                // Node done.
                color[cur.node] = Color::Black;
                stack.pop_back();
                pos.erase(cur.node);
                frames.pop_back();
            }
        }
    }
    return cycles;
}

// ── missing dependencies ──────────────────────────────────────────────────

std::vector<GraphEdge> DependencyGraph::missing_dependencies() const {
    std::vector<GraphEdge> out;
    for (const auto& e : edges_) {
        const auto it = nodes_.find(norm(e.to));
        if (it == nodes_.end() || it->second.missing) out.push_back(e);
    }
    return out;
}

std::vector<std::string> DependencyGraph::dependencies_of(const std::string& node) const {
    std::vector<std::string> out;
    const std::string id = norm(node);
    for (const auto& e : edges_) {
        if (norm(e.from) == id) out.push_back(e.to);
    }
    return out;
}

std::vector<std::string> DependencyGraph::transitive_dependencies(const std::string& node) const {
    const std::string start = norm(node);
    std::set<std::string> visited;
    std::deque<std::string> q{start};
    visited.insert(start);
    while (!q.empty()) {
        const std::string cur = q.front();
        q.pop_front();
        for (const auto& e : edges_) {
            if (norm(e.from) == cur) {
                const std::string tgt = norm(e.to);
                if (visited.insert(tgt).second) q.push_back(tgt);
            }
        }
    }
    visited.erase(start);
    std::vector<std::string> out(visited.begin(), visited.end());
    return out;
}

// ── JSON export ───────────────────────────────────────────────────────────

json::Json DependencyGraph::to_json() const {
    json::Json root = json::Json::object();

    json::Json nodes_arr = json::Json::array();
    for (const auto& kv : nodes_) {
        json::Json n = json::Json::object();
        n.set("id", kv.second.id);
        n.set("normalized", kv.first);
        n.set("is_root", kv.second.is_root);
        n.set("missing", kv.second.missing);
        n.set("category", kv.second.category_name);
        n.set("classified", kv.second.classified);
        nodes_arr.push_back(std::move(n));
    }
    root.set("nodes", std::move(nodes_arr));

    json::Json edges_arr = json::Json::array();
    for (const auto& e : edges_) {
        json::Json j = json::Json::object();
        j.set("from", e.from);
        j.set("to", e.to);
        j.set("delay_load", e.delay_load);
        json::Json fns = json::Json::array();
        for (const auto& f : e.functions) {
            json::Json fj = json::Json::object();
            fj.set("name", f.name.empty() ? std::string() : f.name);
            fj.set("ordinal", f.ordinal);
            fj.set("by_ordinal", f.by_ordinal);
            fj.set("delay_load", f.delay_load);
            fns.push_back(std::move(fj));
        }
        j.set("functions", std::move(fns));
        edges_arr.push_back(std::move(j));
    }
    root.set("edges", std::move(edges_arr));

    json::Json cycles_arr = json::Json::array();
    for (const auto& c : detect_cycles()) {
        json::Json cj = json::Json::array();
        for (const auto& n : c.nodes) cj.push_back(n);
        cycles_arr.push_back(std::move(cj));
    }
    root.set("cycles", std::move(cycles_arr));

    json::Json missing_arr = json::Json::array();
    for (const auto& e : missing_dependencies()) {
        json::Json mj = json::Json::object();
        mj.set("from", e.from);
        mj.set("to", e.to);
        missing_arr.push_back(std::move(mj));
    }
    root.set("missing_dependencies", std::move(missing_arr));

    root.set("node_count", static_cast<std::uint64_t>(node_count()));
    root.set("edge_count", static_cast<std::uint64_t>(edge_count()));
    return root;
}

}  // namespace xbox2pc::graph
