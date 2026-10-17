export const meta = {
  name: "review-asd-essentials",
  description: "Adversarial review of the Essential Eight and ASD Essentials connector",
  phases: [{ title: "Review", detail: "Claude checks the connector against ticket 021" }],
};

const review = await agent(
  [
    "Adversarial review only. Do not edit files, do not commit, and do not praise.",
    "Repository: /Volumes/MacMini/code-projects/hermes-cyber-au",
    "Ticket: tickets/021-conn-asd-essentials.md",
    "Implementation: mcp/asd-essentials/, docs/connectors/asd-essentials.md, mcp/servers.yaml, mcp/egress-allowlist.yaml, README.md connector row.",
    "Verify defects in the code and the shipped snapshot under mcp/asd-essentials/data/.",
    "Hunt for: priority phases presented as maturity scores; invented cloud phase order; Essential Eight controls assigned to the wrong strategy; duplicated controls; incident-reporting controls copied onto every strategy; transition text that is not a quote from ASD; untrusted text left unwrapped; live health that reports ok when the fetch failed; egress gaps; secrets; contract or schema mismatches; Australian English and em dashes in prose we wrote.",
    "Ignore the local knowledge/index.sqlite file. It is a generated index and is gitignored.",
    "Return only verified findings. If you find none that need a code change, verdict is approve and findings is empty.",
  ].join("\n"),
  {
    provider: "claude-code",
    model: "claude-opus-5-5",
    reasoningLevel: "high",
    phase: "Review",
    label: "Adversarial review of asd-essentials",
    schema: {
      type: "object",
      additionalProperties: false,
      required: ["verdict", "findings"],
      properties: {
        verdict: { enum: ["approve", "fix"] },
        findings: {
          type: "array",
          items: {
            type: "object",
            additionalProperties: false,
            required: ["severity", "summary", "file"],
            properties: {
              severity: { enum: ["critical", "high", "medium", "low"] },
              summary: { type: "string" },
              file: { type: "string" },
            },
          },
        },
      },
    },
  },
);

return review;
