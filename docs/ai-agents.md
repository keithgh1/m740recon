# Working with AI agents

Reverse-engineering firmware is a long loop of reading code, forming a hypothesis, writing it down and checking it.  AI coding agents are good at that loop, so m740recon is designed to be driven by them as well as by people.

- [`AGENTS.md`](../AGENTS.md) is the entry point for an agent.  It gives the commands, a step-by-step working loop for a new firmware, the full control-file reference, the rules any change to the code must keep, how to run the tests, and a map of the modules.  [`CLAUDE.md`](../CLAUDE.md) points to it, for tools that look for that name.
- `-j` prints a JSON model whose every key is described in [`docs/json_model.md`](json_model.md), with a format tag (`m740recon-report/1`) to check against.  Agents should parse it rather than the text listing or reports, whose layout may change.
- The same input always produces byte-identical output, so a change in output always means a change in input or in the tool.  The test suite checks this across Python hash seeds.
- `--routine NAME` and `--signal NAME` answer one question at a time, which fits an agent's limited context far better than a 50,000-line listing.
- Every signal access in the JSON says how it was established: `exact` (the instruction names the bit), `derived` (straight-line value tracking), `assumed` (through an address space whose enable bit is not proven), or `path` (one of several locations depending on how the code was reached).  When a value cannot be proven the tool says so, so an agent can tell a fact from an inference.
- `--suggest` drafts a board description from the firmware alone.  An agent refines it in the control file as it learns, records where each fact came from with `source=`, and reruns.  The lint on stderr points at every place the description and the firmware disagree, which is where the next question is.
- Every control-file error names the file and line, so an agent can fix its own mistakes.
