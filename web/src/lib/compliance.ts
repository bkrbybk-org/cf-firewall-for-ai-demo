// ============================================================================
// EDIT THIS FILE to change the compliance mapping page (/compliance).
//   MATRIX      → the overview grid (capability × framework)
//   FRAMEWORKS  → the per-framework detail cards
//
// Honesty rules this content follows — keep them if you edit:
//  - Coverage is graded, never inflated: "full" means the edge actually blocks
//    or records the risk; "partial" means it is detected but policy still sits
//    with the customer; "supporting" means it only supplies evidence.
//  - "none" entries are kept on purpose (see OWASP). Showing what Cloudflare
//    does NOT cover is more credible than a page of all-green ticks.
//  - Control descriptions are written in our own words. ISO/IEC 42001 is a
//    paid standard, so we cite top-level Annex A groups only and never
//    reproduce its control text. NIST AI RMF, OWASP and MITRE ATLAS are
//    public and are cited by their real identifiers. The two Thai frameworks
//    (Bank of Thailand AI Risk Management policy, NCSA AI Security Guidelines)
//    are Thai-language documents — section/phase refs paraphrase their
//    structure, they never reproduce the Thai text verbatim.
// ============================================================================

export type Coverage = "full" | "partial" | "supporting" | "none";
export type Product = "ai-security" | "ai-gateway" | "both" | "neither";

export const COVERAGE_LABEL: Record<Coverage, string> = {
  full: "Full",
  partial: "Partial",
  supporting: "Supporting",
  none: "Out of scope",
};

export const COVERAGE_HELP: Record<Coverage, string> = {
  full: "Cloudflare detects and enforces this at the edge, and records it.",
  partial: "Cloudflare detects and can enforce it, but the policy decision stays with you.",
  supporting: "Cloudflare supplies evidence or telemetry; the control itself is organizational.",
  none: "Not addressed by these two products — application or governance layer.",
};

export const PRODUCT_LABEL: Record<Product, string> = {
  "ai-security": "AI Security for Apps",
  "ai-gateway": "AI Gateway",
  both: "Both products",
  neither: "Neither product",
};

export interface Control {
  id: string; // real identifier, e.g. "MEASURE 2.7"
  title: string; // short control name, paraphrased
  how: string; // how Cloudflare helps — our words, customer-facing
  coverage: Coverage;
  product: Product;
  refs?: string[]; // cross-framework identifiers, e.g. ["LLM01", "AML.T0051"]
  demo?: { label: string; to: string }; // internal route that shows it live
}

export interface Framework {
  id: string;
  label: string; // tab label
  short: string; // matrix column header (compact)
  full: string; // full name + version
  blurb: string; // one line: what the framework is
  note?: string; // scope caveat shown under the blurb
  url: string;
  controls: Control[];
}

// --- Overview matrix ------------------------------------------------------
// Rows are Cloudflare capabilities; `cells` maps a framework id to the
// identifiers that capability maps to. Keep row order = rough demo order.

export interface MatrixRow {
  capability: string;
  detail: string;
  product: Product;
  coverage: Coverage;
  cells: Record<string, string[]>;
}

export const MATRIX: MatrixRow[] = [
  {
    capability: "Prompt injection scoring",
    detail: "cf.llm.prompt.injection_score",
    product: "ai-security",
    coverage: "partial",
    cells: {
      nist: ["MEASURE 2.7"], iso: ["A.6"], owasp: ["LLM01", "LLM07"], atlas: ["AML.T0051", "AML.T0056"],
      bot: ["P2 §3.1"], ncsa: ["Ph.4", "§2.6"],
    },
  },
  {
    capability: "PII detection",
    detail: "cf.llm.prompt.pii_categories",
    product: "ai-security",
    coverage: "full",
    cells: {
      nist: ["MEASURE 2.10"], iso: ["A.7"], owasp: ["LLM02"], atlas: ["AML.T0057"],
      bot: ["P2 §1.3"], ncsa: ["§4.3"],
    },
  },
  {
    capability: "Unsafe topic detection",
    detail: "S1–S14 taxonomy",
    product: "ai-security",
    coverage: "full",
    cells: {
      nist: ["MEASURE 2.6"], iso: ["A.9"], owasp: ["LLM01"], atlas: ["AML.T0054"],
      bot: ["P2 §3.1"], ncsa: ["Ph.4"],
    },
  },
  {
    capability: "Custom topic detection",
    detail: "your own prohibited subjects",
    product: "ai-security",
    coverage: "partial",
    cells: {
      nist: ["GOVERN 1.2"], iso: ["A.2", "A.9"], owasp: [], atlas: [],
      bot: ["P1 §2"], ncsa: ["Ph.1"],
    },
  },
  {
    capability: "Guardrails moderation",
    detail: "prompt and response screening",
    product: "ai-gateway",
    coverage: "partial",
    cells: {
      nist: ["MANAGE 2.3"], iso: ["A.9"], owasp: ["LLM05", "LLM09"], atlas: ["AML.T0054"],
      bot: ["P2 §3.1"], ncsa: ["Ph.4"],
    },
  },
  {
    capability: "Rate limiting and caching",
    detail: "cost and volume control",
    product: "ai-gateway",
    coverage: "full",
    cells: {
      nist: ["MANAGE 2.2"], iso: ["A.6"], owasp: ["LLM10"], atlas: ["AML.T0029"],
      bot: [], ncsa: ["Ph.5"],
    },
  },
  {
    capability: "Logging and analytics",
    detail: "per-request evidence trail",
    product: "both",
    coverage: "full",
    cells: {
      nist: ["MANAGE 4.1", "MEASURE 2.8"], iso: ["A.6", "A.5"], owasp: [], atlas: [],
      bot: ["P1 §3.1"], ncsa: ["Ph.5", "§4.2"],
    },
  },
  {
    capability: "Provider abstraction",
    detail: "fallbacks, retries, one egress point",
    product: "ai-gateway",
    coverage: "supporting",
    cells: {
      nist: ["MAP 4.1"], iso: ["A.10"], owasp: ["LLM03"], atlas: ["AML.T0040"],
      bot: [], ncsa: ["Ph.1"],
    },
  },
];

// --- Per-framework detail -------------------------------------------------

export const FRAMEWORKS: Framework[] = [
  {
    id: "nist",
    label: "NIST AI RMF",
    short: "NIST AI RMF",
    full: "NIST AI Risk Management Framework 1.0 (AI 100-1)",
    blurb:
      "Voluntary US framework organized into four functions — govern, map, measure, manage — with roughly 72 subcategories.",
    note: "Curated: the subcategories these two products meaningfully support, not all 72.",
    url: "https://www.nist.gov/itl/ai-risk-management-framework",
    controls: [
      {
        id: "MEASURE 2.7",
        title: "AI system security and resilience are evaluated",
        how: "Every prompt is scored for injection likelihood at the edge, before the model runs. WAF rules block or log below the threshold you choose, and the score is retained per request.",
        coverage: "partial",
        product: "ai-security",
        refs: ["LLM01", "AML.T0051"],
        demo: { label: "See it on the chat demo", to: "/" },
      },
      {
        id: "MEASURE 2.10",
        title: "Privacy risk is examined and documented",
        how: "PII categories are detected inside the prompt and blocked at the edge, so card numbers, emails, phone numbers and national IDs never reach the model, the provider, or your application logs.",
        coverage: "full",
        product: "ai-security",
        refs: ["LLM02", "AML.T0057"],
        demo: { label: "Send a PII prompt", to: "/" },
      },
      {
        id: "MEASURE 2.6",
        title: "AI system safety risks are evaluated",
        how: "Prompts are classified against the S1–S14 unsafe-topic taxonomy (violence, weapons, self-harm, hate, elections and more). Each category can block or log independently.",
        coverage: "full",
        product: "ai-security",
        refs: ["LLM01", "AML.T0054"],
        demo: { label: "Try an unsafe topic", to: "/" },
      },
      {
        id: "MEASURE 2.8",
        title: "Transparency and accountability are examined",
        how: "Each request carries a Cloudflare ray ID that ties the user-visible outcome to the exact edge event, matched rule and detection scores — an auditable chain from prompt to decision.",
        coverage: "supporting",
        product: "both",
        demo: { label: "Read an edge verdict", to: "/" },
      },
      {
        id: "MEASURE 3.1",
        title: "Identified risks are tracked over time",
        how: "The analytics dashboard trends blocked versus logged events, top firing rules and the injection-score distribution across your chosen window, so risk exposure is measured rather than assumed.",
        coverage: "partial",
        product: "both",
        demo: { label: "Open analytics", to: "/analytics" },
      },
      {
        id: "MANAGE 2.2",
        title: "Mechanisms sustain the value of deployed AI",
        how: "AI Gateway caching removes repeat inference cost, rate limiting caps runaway spend and abuse, and per-request token and cost data makes consumption visible.",
        coverage: "full",
        product: "ai-gateway",
        refs: ["LLM10"],
        demo: { label: "See caching", to: "/" },
      },
      {
        id: "MANAGE 2.3",
        title: "Procedures respond to previously unknown risks",
        how: "Rules can move from log to block without redeploying the application, and Gateway Guardrails add a second moderation layer on both prompt and response — so a newly discovered risk is contained in minutes.",
        coverage: "partial",
        product: "both",
        refs: ["LLM05"],
        demo: { label: "Try Guardrails", to: "/" },
      },
      {
        id: "MANAGE 4.1",
        title: "Post-deployment monitoring is implemented",
        how: "Every request is recorded with its detection scores, matched rule, token count and cost, and is queryable through analytics — continuous monitoring without instrumenting the application.",
        coverage: "full",
        product: "both",
        demo: { label: "Open analytics", to: "/analytics" },
      },
      {
        id: "GOVERN 1.2",
        title: "Trustworthy AI characteristics are in policy",
        how: "Custom topics let you encode your own acceptable-use policy as an enforceable edge rule. Log-only mode lets you observe real prompt traffic first, so thresholds come from evidence rather than guesswork.",
        coverage: "supporting",
        product: "ai-security",
      },
      {
        id: "MAP 4.1",
        title: "Risks from third-party components are mapped",
        how: "AI Gateway is a single egress point for every model provider, with per-provider logs, fallbacks and retries — so third-party model dependencies are inventoried and controlled in one place.",
        coverage: "supporting",
        product: "ai-gateway",
        refs: ["LLM03"],
      },
    ],
  },
  {
    id: "iso",
    label: "ISO 42001",
    short: "ISO 42001",
    full: "ISO/IEC 42001:2023 — AI management system (AIMS)",
    blurb:
      "Certifiable management-system standard for AI. Annex A carries the reference controls, grouped A.2 through A.10.",
    note: "ISO/IEC 42001 is a paid standard. We cite top-level Annex A groups only and describe them in our own words — check the exact sub-control text against your own copy.",
    url: "https://www.iso.org/standard/81230.html",
    controls: [
      {
        id: "A.5",
        title: "Assessing impacts of AI systems",
        how: "Detection telemetry shows what your users actually send: how many prompts carry PII, how many attempt injection, which topics recur. That turns an impact assessment from a paper exercise into measured evidence.",
        coverage: "supporting",
        product: "both",
        demo: { label: "Open analytics", to: "/analytics" },
      },
      {
        id: "A.6",
        title: "AI system life cycle",
        how: "Pre-deployment, the attack library and scripted demo exercise your rules against known attack classes. In operation, every request is scored, logged and attributable — covering the verification and monitoring stages of the life cycle.",
        coverage: "partial",
        product: "both",
        demo: { label: "Run the scripted demo", to: "/" },
      },
      {
        id: "A.7",
        title: "Data for AI systems",
        how: "PII detection stops personal data entering prompts, model providers and downstream logs. Token counting records how much data each request carries.",
        coverage: "partial",
        product: "ai-security",
        refs: ["LLM02"],
        demo: { label: "Send a PII prompt", to: "/" },
      },
      {
        id: "A.8",
        title: "Information for interested parties",
        how: "Blocked requests return a response you control, so users are told why a prompt was refused. Retained logs support incident notification and user enquiries.",
        coverage: "supporting",
        product: "ai-security",
      },
      {
        id: "A.9",
        title: "Use of AI systems",
        how: "Unsafe-topic and custom-topic rules encode acceptable use and enforce it on every request, and Gateway Guardrails screen the model's responses as well as the prompts.",
        coverage: "partial",
        product: "both",
        refs: ["LLM01", "LLM05"],
        demo: { label: "Try Guardrails", to: "/" },
      },
      {
        id: "A.10",
        title: "Third-party and customer relationships",
        how: "AI Gateway centralizes every model-provider call behind one control point, with its own logs, authentication, fallbacks and retries — making supplier dependencies visible and governable.",
        coverage: "supporting",
        product: "ai-gateway",
        refs: ["LLM03"],
        demo: { label: "See the gateway", to: "/" },
      },
      {
        id: "A.2",
        title: "AI policy",
        how: "Custom topics turn written policy statements into enforceable rules. Log-only mode measures how often policy is tested in practice before you switch to blocking.",
        coverage: "supporting",
        product: "ai-security",
      },
    ],
  },
  {
    id: "owasp",
    label: "OWASP LLM top 10",
    short: "OWASP",
    full: "OWASP Top 10 for LLM Applications (2025)",
    blurb:
      "The community list of the ten most critical LLM application risks. All ten are listed here, including the four these products do not address.",
    url: "https://genai.owasp.org/llm-top-10/",
    controls: [
      {
        id: "LLM01",
        title: "Prompt injection",
        how: "Injection likelihood is scored on every prompt at the edge, before the model runs. Low scores are blocked; the threshold is yours to set, and log-only mode shows what you would have blocked.",
        coverage: "full",
        product: "ai-security",
        refs: ["MEASURE 2.7", "AML.T0051"],
        demo: { label: "Run the red-team corpus", to: "/redteam" },
      },
      {
        id: "LLM02",
        title: "Sensitive information disclosure",
        how: "PII categories are detected in-prompt and blocked before the model or provider ever sees them. Gateway DLP extends the same idea to secrets and credentials.",
        coverage: "full",
        product: "both",
        refs: ["MEASURE 2.10", "AML.T0057"],
        demo: { label: "Send a PII prompt", to: "/" },
      },
      {
        id: "LLM10",
        title: "Unbounded consumption",
        how: "Gateway rate limiting caps request volume, caching removes duplicate inference entirely, and per-request token and cost figures make spend visible before it becomes a bill.",
        coverage: "full",
        product: "ai-gateway",
        refs: ["MANAGE 2.2", "AML.T0029"],
        demo: { label: "See caching", to: "/" },
      },
      {
        id: "LLM07",
        title: "System prompt leakage",
        how: "Extraction attempts read as prompt injection and are scored the same way, so 'repeat your instructions' style prompts are caught. Cloudflare cannot know what your system prompt contains, so keeping secrets out of it remains your responsibility.",
        coverage: "partial",
        product: "ai-security",
        refs: ["MEASURE 2.7", "AML.T0056"],
        demo: { label: "Try prompt leakage", to: "/" },
      },
      {
        id: "LLM05",
        title: "Improper output handling",
        how: "Gateway Guardrails screen the model's response, not just the prompt, and block unsafe output before it reaches your application. Safe handling of that output in your own code is still on you.",
        coverage: "partial",
        product: "ai-gateway",
        refs: ["MANAGE 2.3"],
        demo: { label: "Try Guardrails", to: "/" },
      },
      {
        id: "LLM09",
        title: "Misinformation",
        how: "Guardrails can screen responses for categories of harmful content, which catches some classes of harmful misinformation. Factual accuracy is a model and grounding problem, not a network control.",
        coverage: "supporting",
        product: "ai-gateway",
      },
      {
        id: "LLM03",
        title: "Supply chain",
        how: "AI Gateway is one authenticated egress point for every provider, with fallbacks, retries and per-provider logs. It governs the model supply chain at runtime but does not vet model provenance.",
        coverage: "supporting",
        product: "ai-gateway",
        refs: ["MAP 4.1", "A.10"],
      },
      {
        id: "LLM04",
        title: "Data and model poisoning",
        how: "Poisoning happens at training and fine-tuning time, upstream of any inference-path control. Neither product addresses it — pair them with controls on your training pipeline and model sourcing.",
        coverage: "none",
        product: "neither",
      },
      {
        id: "LLM06",
        title: "Excessive agency",
        how: "Limiting what tools and permissions an agent holds is an application-design decision. Neither product constrains agent capability, though gateway logs do show what an agent called.",
        coverage: "none",
        product: "neither",
      },
      {
        id: "LLM08",
        title: "Vector and embedding weaknesses",
        how: "Retrieval and embedding-store security sits inside your RAG architecture. Neither product inspects vector stores — look at Cloudflare Vectorize and AI Search controls instead.",
        coverage: "none",
        product: "neither",
      },
    ],
  },
  {
    id: "atlas",
    label: "MITRE ATLAS",
    short: "MITRE ATLAS",
    full: "MITRE ATLAS — adversarial threat landscape for AI systems",
    blurb:
      "Adversary tactics and techniques observed against AI systems, structured like MITRE ATT&CK.",
    note: "Curated: the LLM-facing techniques these products detect or mitigate, not the whole matrix.",
    url: "https://atlas.mitre.org/",
    controls: [
      {
        id: "AML.T0051",
        title: "LLM prompt injection",
        how: "Direct injection attempts are scored and blocked at the edge before reaching the model. Indirect injection carried inside retrieved content is only caught if that content passes back through a scanned endpoint.",
        coverage: "partial",
        product: "ai-security",
        refs: ["LLM01", "MEASURE 2.7"],
        demo: { label: "Run the red-team corpus", to: "/redteam" },
      },
      {
        id: "AML.T0054",
        title: "LLM jailbreak",
        how: "Jailbreak framings — persona overrides, fictional-context wrappers, 'ignore your rules' — score as injection, and the harmful payload they carry is independently caught by unsafe-topic classification.",
        coverage: "full",
        product: "both",
        refs: ["LLM01"],
        demo: { label: "Try a jailbreak", to: "/" },
      },
      {
        id: "AML.T0057",
        title: "LLM data leakage",
        how: "PII in prompts is detected and blocked before it reaches the model or provider, and Gateway DLP screens for credentials and secrets in both directions.",
        coverage: "full",
        product: "both",
        refs: ["LLM02", "MEASURE 2.10"],
        demo: { label: "Send a PII prompt", to: "/" },
      },
      {
        id: "AML.T0056",
        title: "LLM meta prompt extraction",
        how: "Prompts engineered to dump system instructions score as injection and are blocked. This raises the cost of extraction rather than making it impossible — do not put secrets in a system prompt.",
        coverage: "partial",
        product: "ai-security",
        refs: ["LLM07"],
        demo: { label: "Try prompt leakage", to: "/" },
      },
      {
        id: "AML.T0029",
        title: "Denial of ML service",
        how: "Gateway rate limiting caps request volume per gateway, caching absorbs repeated identical prompts, and Cloudflare's standard DDoS and bot protections sit in front of the endpoint.",
        coverage: "partial",
        product: "ai-gateway",
        refs: ["LLM10"],
        demo: { label: "See caching", to: "/" },
      },
      {
        id: "AML.T0040",
        title: "ML model inference API access",
        how: "An authenticated gateway plus WAF rules on the inference endpoint restrict who can reach the model at all, and every call is logged with its origin.",
        coverage: "supporting",
        product: "both",
        refs: ["LLM03"],
      },
    ],
  },
  {
    id: "bot",
    label: "BOT AI Risk",
    short: "BOT",
    full: "Bank of Thailand — AI risk management policy (2025)",
    blurb:
      "Regulator policy for financial institutions and supervised payment providers. Two parts: Governance, and Development & Security (Data / Model / Cyber).",
    note: "Thai-language BOT policy (แนวนโยบาย, 12 Sep 2025). Section refs (Part 1/2 §n) paraphrase its structure — no Thai text is reproduced. Confirm against the official document for a regulated engagement.",
    url: "https://www.bot.or.th/",
    controls: [
      {
        id: "Part 2 · 3.1",
        title: "Cyber risk — content filtering (prompt + response)",
        how: "The policy asks for filtering both the incoming prompt (prompt filtering) and the model's output (response filtering). Firewall for AI blocks unsafe prompts at the edge; AI Gateway Guardrails screens the response — exactly the two halves this control names.",
        coverage: "full",
        product: "both",
        refs: ["LLM01", "LLM05"],
        demo: { label: "See prompt filtering", to: "/" },
      },
      {
        id: "Part 2 · 3.3",
        title: "Monitor emerging AI threats",
        how: "The policy points to OWASP LLM Top 10, OWASP ML Top 10 and MITRE ATLAS as references. This demo's detections map directly onto those catalogues, and analytics trends attack activity over time.",
        coverage: "supporting",
        product: "both",
        refs: ["LLM01", "AML.T0051"],
        demo: { label: "Open analytics", to: "/analytics" },
      },
      {
        id: "Part 2 · 1.3",
        title: "Data risk — prevent data leakage",
        how: "PII detection blocks personal data in prompts before the model or provider sees it — an input-sanitization control at the edge. Access control to your own data stores stays with you.",
        coverage: "partial",
        product: "ai-security",
        refs: ["LLM02"],
        demo: { label: "Send a PII prompt", to: "/" },
      },
      {
        id: "Part 2 · 3.2",
        title: "Continuous attack testing",
        how: "The attack library and one-click demo exercise your rules against prompt-injection and jailbreak classes on demand. Data-poisoning and adversarial-training tests are outside an inference-path control.",
        coverage: "supporting",
        product: "ai-security",
        refs: ["AML.T0051"],
        demo: { label: "Run the scripted demo", to: "/" },
      },
      {
        id: "Part 1 · 3.1",
        title: "Identify AI risks and monitor against risk appetite",
        how: "Per-request detection scores plus the analytics dashboard give continuous, measurable evidence of how often prompts hit each risk category — the ongoing monitoring the policy requires.",
        coverage: "supporting",
        product: "both",
        demo: { label: "Open analytics", to: "/analytics" },
      },
      {
        id: "Part 1 · 2",
        title: "Responsible-AI policy (FEAT) as enforceable rules",
        how: "Custom topics turn an acceptable-use policy into edge rules, and log-only mode lets you measure before enforcing. The FEAT principles themselves (fairness, ethics, accountability, transparency) are governance, not a network control.",
        coverage: "supporting",
        product: "ai-security",
      },
      {
        id: "Part 1 · 3.2",
        title: "Human oversight of high-impact AI decisions",
        how: "Blocking gives you an enforcement point to route a flagged request to a human, but the human-in-the-loop / human-over-the-loop design is an application decision.",
        coverage: "none",
        product: "neither",
      },
      {
        id: "Part 2 · 2.3",
        title: "Reduce Generative-AI hallucination",
        how: "The policy suggests RAG and prompt engineering to cut hallucination — both live in your application and model layer, not at the network edge.",
        coverage: "none",
        product: "neither",
      },
    ],
  },
  {
    id: "ncsa",
    label: "NCSA AI Security",
    short: "NCSA",
    full: "NCSA Thailand — AI Security Guidelines (2025)",
    blurb:
      "National guidance built on ISO/IEC 42001, ENISA and OWASP: a 7-phase secure AI lifecycle (phases 0–6) plus a governance chapter.",
    note: "Thai-language NCSA (สกมช.) guidance, 30 Sep 2025. Phase / section refs paraphrase its structure — no Thai text is reproduced.",
    url: "https://www.ncsa.or.th/",
    controls: [
      {
        id: "§2.6 threats",
        title: "Prompt injection",
        how: "Injection likelihood is scored on every prompt at the edge and blocked below your threshold — the headline threat the guideline names (alongside data poisoning and model evasion).",
        coverage: "full",
        product: "ai-security",
        refs: ["LLM01", "AML.T0051"],
        demo: { label: "Try an injection", to: "/" },
      },
      {
        id: "Phase 5",
        title: "Secure operation and maintenance",
        how: "Every request is logged with detection scores, matched rules, tokens and cost, and analytics trends threat activity — continuous operational monitoring of the deployed model without instrumenting it.",
        coverage: "full",
        product: "both",
        demo: { label: "Open analytics", to: "/analytics" },
      },
      {
        id: "Phase 4",
        title: "Secure deployment and use",
        how: "Firewall for AI and AI Gateway sit in front of the inference endpoint, screening every prompt and response in production — runtime protection for the deployed model.",
        coverage: "partial",
        product: "both",
        refs: ["LLM01", "LLM05"],
        demo: { label: "See it on the chat demo", to: "/" },
      },
      {
        id: "Phase 3",
        title: "Secure verification and review",
        how: "The attack library and scripted demo act as a pre-deployment test harness against known prompt-injection and jailbreak classes.",
        coverage: "supporting",
        product: "ai-security",
        refs: ["AML.T0054"],
        demo: { label: "Run the scripted demo", to: "/" },
      },
      {
        id: "§4.3 PDPA",
        title: "Thai PDPA — personal data protection",
        how: "PII detection blocks personal data from entering prompts and downstream provider logs, supporting PDPA obligations on the inference path.",
        coverage: "partial",
        product: "ai-security",
        refs: ["LLM02"],
        demo: { label: "Send a PII prompt", to: "/" },
      },
      {
        id: "§4.2 risk",
        title: "Integrate AI risk into the org risk framework",
        how: "Detection telemetry and logs feed your enterprise risk process with measured AI-risk data; wiring that into the framework itself is organizational.",
        coverage: "supporting",
        product: "both",
        demo: { label: "Open analytics", to: "/analytics" },
      },
      {
        id: "Phase 1",
        title: "Secure model supply chain",
        how: "AI Gateway is one authenticated egress point for every model provider, with per-provider logs and fallbacks — governing the runtime model supply chain, though it does not vet model provenance.",
        coverage: "supporting",
        product: "ai-gateway",
        refs: ["LLM03"],
      },
      {
        id: "§2.6 threats",
        title: "Data poisoning",
        how: "Poisoning happens at training time, upstream of any inference-path control — pair this guideline with controls on your training pipeline and data sourcing.",
        coverage: "none",
        product: "neither",
        refs: ["LLM04"],
      },
    ],
  },
];
