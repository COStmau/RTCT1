"""Where things go on the page, computed from the learned machine. No positions are typed in.

  icicle(root)               the unmerged prefix tree as stacked bars: depth down, visits across
  layered(pdfa)              the merged machine as columns by distance from the start state
  pta_to_pdfa_map(pdfa, ...) which prefix-tree nodes each final state absorbed
  settled_steps(nodes, steps) the step at which each prefix-tree node joins a kept state

All coordinates are in [0, 1]; the renderer scales them to whatever canvas it has. Ties are
broken by symbol or state id, so the same machine always draws the same way.
"""
from methods.scores import pdfa_states_in_order

BARYCENTER_SWEEPS = 4


def icicle(root):
    """Prefix-tree nodes breadth-first, children by symbol, width proportional to visits.

    A node's span is shared by its children in proportion to their visits; the traces that
    end at the node keep the remainder at the right, so children never overfill the parent.
    """
    nodes = [{"id": 0, "parent": None, "symbol": None, "path": (), "depth": 0,
              "visits": root.visits, "final": root.final, "x0": 0.0, "x1": 1.0}]
    queue = [(root, nodes[0])]
    while queue:
        node, placed = queue.pop(0)
        cursor, span = placed["x0"], placed["x1"] - placed["x0"]
        for symbol in sorted(node.children):
            child = node.children[symbol]
            width = span * child.visits / node.visits if node.visits else 0.0
            entry = {"id": len(nodes), "parent": placed["id"], "symbol": symbol,
                     "path": placed["path"] + (symbol,), "depth": placed["depth"] + 1,
                     "visits": child.visits, "final": child.final,
                     "x0": cursor, "x1": cursor + width}
            nodes.append(entry)
            queue.append((child, entry))
            cursor += width
    return nodes


def layered(pdfa):
    """States in columns by breadth-first depth, ordered in each column by barycenters.

    States are numbered as `pdfa_states_in_order` numbers them, the same ids `plot_pdfa`
    prints. Within a column, a state sits near the mean position of its neighbours in the
    adjacent columns, alternating left-to-right and right-to-left sweeps.
    """
    order = pdfa_states_in_order(pdfa)
    ids = {id(node): index for index, node in enumerate(order)}
    edges, depth = [], {0: 0}
    for index, node in enumerate(order):
        for symbol, (child, prob) in sorted(pdfa.probs[id(node)][1].items()):
            target = ids[id(child)]
            edges.append({"src": index, "dst": target, "symbol": symbol, "prob": float(prob),
                          "count": int(node.edge[symbol])})
            depth.setdefault(target, depth[index] + 1)
    columns = {}
    for index in range(len(order)):
        columns.setdefault(depth[index], []).append(index)
    neighbours = {index: set() for index in range(len(order))}
    for edge in edges:
        if edge["src"] != edge["dst"]:
            neighbours[edge["src"]].add(edge["dst"])
            neighbours[edge["dst"]].add(edge["src"])

    position = {}

    def place(column):
        for rank, index in enumerate(column):
            position[index] = (rank + 0.5) / len(column)

    for column in columns.values():
        place(column)
    deepest = max(columns)
    for sweep in range(BARYCENTER_SWEEPS):
        step = 1 if sweep % 2 == 0 else -1
        for level in (range(1, deepest + 1) if step == 1 else range(deepest - 1, -1, -1)):
            anchor = level - step

            def centre(index):
                near = [position[n] for n in neighbours[index] if depth[n] == anchor]
                return (sum(near) / len(near) if near else position[index], index)
            columns[level] = sorted(columns[level], key=centre)
            place(columns[level])

    # entries: how often training walked into the state, which is what a test trace's
    # visits count; the start state's visits also count every trace that began there
    entries = {index: 0 for index in range(len(order))}
    for edge in edges:
        entries[edge["dst"]] += edge["count"]
    states = [{"id": index, "visits": int(node.visits), "entries": entries[index],
               "x": depth[index] / deepest if deepest else 0.0, "y": position[index]}
              for index, node in enumerate(order)]
    return {"states": states, "edges": edges}


def pta_to_pdfa_map(pdfa, nodes):
    """{state id: [prefix-tree node ids]}: each tree path walked through the final machine.

    Merging keeps every training path, so the state a path reaches in the final machine is
    the state its prefix-tree node was folded into.
    """
    ids = {id(node): index for index, node in enumerate(pdfa_states_in_order(pdfa))}
    mapping = {}
    for node in nodes:
        state = pdfa.root
        for symbol in node["path"]:
            state, _ = pdfa.transition(state, symbol)
        mapping.setdefault(ids[id(state)], []).append(node["id"])
    return mapping


def settled_steps(nodes, steps, root=None):
    """{prefix-tree id: the step after which it belongs to a kept (red) state; 0 = from start}.

    Replays the red-blue steps on the prefix tree's ids with the same fold as
    methods.pdfa._fold_into. A merge folds the candidate into a red state, but the
    candidate's children only fold into that red state's children, which may still be
    candidates themselves, so they settle later, when their own group turns red or folds into
    a red one. Colouring a merged subtree at once would show states that do not exist yet.

    The replay mirrors the learner move for move, ids standing for its node objects: a folded
    state is never deleted (the learner's stale references stay valid too, and once merges
    make loops a fold can reach them again), a state folded into itself is skipped, and a
    candidate's owner is found the way the learner's fringe finds it, by scanning the red
    states in the order they turned red.

    Child order matters: when two folds add the same symbol to a state, the first one wins,
    and the learner walks each state's children in insertion order (the order the symbols
    first appeared in the traces), not sorted. Pass the prefix tree `root` the nodes were
    laid out from (icicle(root)) so the replay uses that order; without it, symbol order is
    assumed, which only agrees when no fold adds a symbol twice.
    """
    by_path = {node["path"]: node["id"] for node in nodes}
    children = {node["id"]: {} for node in nodes}
    if root is not None:
        stack = [(root, ())]
        while stack:
            source, path = stack.pop()
            for symbol, child in source.children.items():   # insertion order, as learned
                children[by_path[path]][symbol] = by_path[path + (symbol,)]
                stack.append((child, path + (symbol,)))
    else:
        for node in nodes:
            if node["parent"] is not None:
                children[node["parent"]][node["symbol"]] = node["id"]
    members = {node["id"]: {node["id"]} for node in nodes}
    red = [nodes[0]["id"]]
    settled = {nodes[0]["id"]: 0}

    def fold(target, other):
        if target == other:          # as methods.pdfa._fold_into
            return
        members[target] |= members[other]
        for symbol, child in list(children[other].items()):
            if symbol in children[target]:
                fold(children[target][symbol], child)
            else:
                children[target][symbol] = child

    def owner_of(blue):
        """The red state and symbol whose edge leads to `blue`, as the learner's fringe[0]."""
        reds = set(red)
        for state in red:
            for symbol, child in sorted(children[state].items()):
                if child == blue and child not in reds:
                    return state, symbol
        raise ValueError(f"candidate {blue} hangs off no kept state; the steps do not replay")

    for index, step in enumerate(steps, start=1):
        blue, target = step["blue"], step["red"]
        if step["kind"] == "promote":
            red.append(blue)
            newly = members[blue]
        else:
            owner, symbol = owner_of(blue)
            children[owner][symbol] = target
            fold(target, blue)
            newly = members[target]
        for member in newly:
            settled.setdefault(member, index)
    for node in nodes:
        settled.setdefault(node["id"], len(steps))
    return settled
