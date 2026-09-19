/**
 * Groq LLM Service (Gemini replacement)
 * Single integration point for all AI-assisted features in RepoShield.
 *
 * Model routing:
 * - llama-3.1-8b-instant    -> fast tasks & outreach drafting
 * - llama-3.3-70b-versatile -> complex analysis & code patch generation
 *
 * Error contract: every public method resolves with a structured payload that
 * always contains `success`, and on failure `error` + `errorCode` so the UI can
 * notify the user (missing key, rate limited, etc.) without crashing handlers.
 */

import Groq from 'groq-sdk';
import type {
  OSVVulnerability,
  ProjectAnalysis,
} from '../../src/types/index.ts';

/** Fast tasks & outreach drafting */
export const GROQ_FAST_MODEL = 'llama-3.1-8b-instant';
/** Complex analysis & code patch generation */
export const GROQ_HEAVY_MODEL = 'llama-3.3-70b-versatile';

export type GroqErrorCode =
  | 'missing_api_key'
  | 'rate_limited'
  | 'api_error'
  | 'invalid_response';

export interface GroqStructuredError {
  success: false;
  error: string;
  errorCode: GroqErrorCode;
  /** HTTP status the caller should propagate (e.g. 429 -> 429, missing key -> 503) */
  httpStatus: number;
}

export interface RemediationResult {
  success: true;
  title: string;
  patch: string;
  body: string;
  model: string;
  provider: 'groq';
  latencyMs: number;
}

export interface OutreachResult {
  success: true;
  subject: string;
  body: string;
  githubIssueTitle: string;
  githubIssueMarkdown: string;
  prTitle: string;
  prBody: string;
  model: string;
  provider: 'groq';
  latencyMs: number;
}

export type GroqResult<T> = T | GroqStructuredError;

const MISSING_KEY_MESSAGE =
  'GROQ_API_KEY is not configured on the server. Add your Groq API key via the key button in the header (stored locally in your browser) or set GROQ_API_KEY on the server to enable AI features.';

const REMEDIATION_SYSTEM_PROMPT = `You are RepoShield Remediation Bot, an automated open-source security engineer.
You generate dependency-bump remediation plans for known npm CVEs.

Rules:
- Respond with a SINGLE JSON object and nothing else. No markdown fences, no commentary.
- JSON shape: {"title": string, "patch": string, "body": string}
- "title": conventional-commit style, e.g. "fix(security): bump body-parser to ^1.20.6 to resolve CVE-2026-12590"
- "patch": either a unified diff (--- a/package.json / +++ b/package.json with @@ hunks) or, if a diff is not possible, the exact "pkg": "^x.y.z" version-bump statement to apply.
- "body": detailed PR markdown body with sections "## Impact", "## Vulnerability", "## Patch", "## Test Verification" and a verification checklist.
- Only bump the affected package(s) to the minimum fixed version supplied; never invent versions.
- Be deterministic: state facts from the advisory only, no hedging, no alternative approaches.`;

const OUTREACH_SYSTEM_PROMPT = `You are RepoShield Outreach Bot, a friendly, low-pressure open-source community assistant.
You draft supportive maintainer outreach about a security patch proposal.

Rules:
- Respond with a SINGLE JSON object and nothing else. No markdown fences, no commentary.
- JSON shape: {"subject": string, "body": string, "githubIssueTitle": string, "githubIssueMarkdown": string, "prTitle": string, "prBody": string}
- Tone: celebratory and educational. Congratulate the maintainer on growth milestones. Zero blame.
- The email body is plain text; the GitHub issue markdown and PR body are GitHub-flavored markdown.
- Keep each field under 250 words. Never include fabricated CVE ids or version numbers beyond the ones provided.`;

/** Server-side trace log for remediation/outreach generation diagnostics. */
function traceGq(step: string, detail: string): void {
  console.log(`[groq] ${new Date().toISOString()} ${step}: ${detail}`);
}

/** Advisory text clamp: prompts carry ONLY the advisory segment, never raw
 * lockfiles or full disclosure dumps that can blow the context window. */
const MAX_ADVISORY_DETAIL_CHARS = 2000;

function clampAdvisoryText(text: string | undefined, maxChars = MAX_ADVISORY_DETAIL_CHARS): string {
  const clean = (text || '').replace(/[ 	]+\n/g, '\n').trim();
  return clean.length <= maxChars ? clean : `${clean.slice(0, maxChars)}\n[advisory text truncated]`;
}

/**
 * Deterministic programmatic remediation - used verbatim when the model output
 * fails to parse or the request times out. Bumps the dependency to the scanner-
 * identified fixed version and composes the standard PR title/body.
 */
function buildDeterministicRemediation(vuln: OSVVulnerability, latencyMs: number): RemediationResult {
  const cveId = vuln.cveId || vuln.id;
  const title = `fix(security): bump ${vuln.packageName} to ^${vuln.fixedVersion} to resolve ${cveId}`;
  const patch = [
    '--- a/package.json',
    '+++ b/package.json',
    '@@',
    `-  "${vuln.packageName}": "${vuln.currentVersion}"`,
    `+  "${vuln.packageName}": "^${vuln.fixedVersion}"`,
  ].join('\n');
  const body = [
    '## Impact',
    vuln.summary || `Known vulnerability in ${vuln.packageName} ${vuln.currentVersion}.`,
    '',
    '## Vulnerability',
    clampAdvisoryText(vuln.details, 1200) || `See advisory: ${vuln.references?.[0]?.url || cveId}`,
    '',
    '## Patch',
    `Bump \`${vuln.packageName}\` from \`${vuln.currentVersion}\` to \`^${vuln.fixedVersion}\` (minimum fixed release per the advisory).`,
    '',
    '## Test Verification',
    '- [ ] `npm install` completes without errors',
    `- [ ] \`npm audit\` no longer reports ${cveId}`,
    '- [ ] Test suite passes on the patched dependency set',
    '',
    '---',
    '_Automated remediation drafted by **RepoShield**._',
  ].join('\n');
  return { success: true, title, patch, body, model: 'deterministic-fallback', provider: 'groq', latencyMs };
}

/** True when a server-side Groq key is configured. */
export function isGroqConfigured(): boolean {
  return Boolean(process.env.GROQ_API_KEY && process.env.GROQ_API_KEY.trim().length > 0);
}

/**
 * Groq rotates model availability per account over time. If the requested
 * primary model no longer exists (`model_not_found`), we fall back to the best
 * chat-capable model the account actually has, scoring by size/class so heavy
 * tasks stay on large models and fast tasks stay on small ones.
 */
const NON_CHAT_MODEL_PATTERN = /guard|whisper|orpheus|embed|safeguard|tts|prompt-guard/i;

let cachedModelList: string[] | null = null;

async function fetchChatCapableModels(apiKey: string): Promise<string[]> {
  if (cachedModelList) return cachedModelList;
  const client = new Groq({ apiKey });
  const list = await client.models.list();
  cachedModelList = (list.data || [])
    .map((m: { id: string }) => m.id)
    .filter((id: string) => !NON_CHAT_MODEL_PATTERN.test(id));
  return cachedModelList;
}

function scoreModelForTask(modelId: string, tier: 'fast' | 'heavy'): number {
  const id = modelId.toLowerCase();
  if (tier === 'heavy') {
    if (/70b/.test(id)) return 5;
    if (/120b/.test(id)) return 4;
    if (/compound/.test(id) && !/mini/.test(id)) return 3;
    if (/llama/.test(id)) return 2;
    return 1;
  }
  if (/8b/.test(id)) return 5;
  if (/20b/.test(id)) return 4;
  if (/mini/.test(id)) return 3;
  if (/llama/.test(id)) return 2;
  return 1;
}

async function resolveFallbackModel(apiKey: string, tier: 'fast' | 'heavy'): Promise<string | null> {
  try {
    const candidates = await fetchChatCapableModels(apiKey);
    if (candidates.length === 0) return null;
    return candidates.reduce((best, cur) =>
      scoreModelForTask(cur, tier) > scoreModelForTask(best, tier) ? cur : best
    );
  } catch {
    return null;
  }
}

function isModelNotFoundError(err: any): boolean {
  return err?.status === 404 && /model_not_found|does not exist/i.test(String(err?.message || ''));
}

/** Map any thrown error to the structured error payload. */
function toStructuredError(err: unknown): GroqStructuredError {
  const anyErr = err as any;
  const status: number | undefined = anyErr?.status ?? anyErr?.response?.status;

  if (status === 429) {
    return {
      success: false,
      error:
        'Groq API rate limit reached (HTTP 429). Please wait a moment and try again, or provide your own Groq API key.',
      errorCode: 'rate_limited',
      httpStatus: 429,
    };
  }
  if (status === 401 || status === 403) {
    return {
      success: false,
      error: 'Groq API rejected the provided key (authentication failed). Check the GROQ_API_KEY.',
      errorCode: 'api_error',
      httpStatus: 502,
    };
  }
  if (anyErr?.code === 'missing_api_key') {
    return {
      success: false,
      error: MISSING_KEY_MESSAGE,
      errorCode: 'missing_api_key',
      httpStatus: 503,
    };
  }
  return {
    success: false,
    error: `Groq API error: ${anyErr?.message || 'Unknown error calling Groq.'}`,
    errorCode: 'api_error',
    httpStatus: 502,
  };
}

/**
 * Lenient JSON parse: first tries strict JSON.parse; on failure repairs the
 * common defects reasoning models emit — raw control characters inside string
 * literals and truncation from token caps (unclosed strings / objects).
 */
function parseJsonLoose(text: string): Record<string, unknown> | null {
  try {
    return JSON.parse(text);
  } catch {
    // fallthrough to repair
  }

  let repaired = '';
  let inString = false;
  let escaped = false;
  for (const ch of text) {
    if (inString) {
      if (escaped) {
        repaired += ch;
        escaped = false;
        continue;
      }
      if (ch === '\\') {
        repaired += ch;
        escaped = true;
        continue;
      }
      if (ch === '"') {
        inString = false;
        repaired += ch;
        continue;
      }
      if (ch === '\n') {
        repaired += '\\n';
        continue;
      }
      if (ch === '\r') {
        repaired += '\\r';
        continue;
      }
      if (ch === '\t') {
        repaired += '\\t';
        continue;
      }
      repaired += ch;
      continue;
    }
    if (ch === '"') {
      inString = true;
      repaired += ch;
      continue;
    }
    repaired += ch;
  }
  if (inString) repaired += '"';

  // Close unbalanced braces / brackets left by truncation.
  let braceDepth = 0;
  let bracketDepth = 0;
  let inS = false;
  let esc = false;
  for (const ch of repaired) {
    if (inS) {
      if (esc) {
        esc = false;
        continue;
      }
      if (ch === '\\') {
        esc = true;
        continue;
      }
      if (ch === '"') inS = false;
      continue;
    }
    if (ch === '"') inS = true;
    else if (ch === '{') braceDepth++;
    else if (ch === '}') braceDepth--;
    else if (ch === '[') bracketDepth++;
    else if (ch === ']') bracketDepth--;
  }
  repaired += '}'.repeat(Math.max(0, braceDepth)) + ']'.repeat(Math.max(0, bracketDepth));

  try {
    const reparsed = JSON.parse(repaired);
    return typeof reparsed === 'object' && reparsed !== null ? (reparsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Strip markdown fences / prose and parse the first JSON object in the output. */
function extractJson(raw: string): Record<string, unknown> {
  let text = raw.trim();
  const fenceMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fenceMatch) text = fenceMatch[1].trim();
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end === -1 || end <= start) {
    throw new Error('Model output did not contain a JSON object');
  }
  const slice = text.slice(start, end + 1);
  const strict = parseJsonLoose(slice);
  if (strict) return strict;
  // Truncation may have cut off the final closing brace; retry on the raw text.
  const loose = parseJsonLoose(text.slice(start));
  if (loose) return loose;
  throw new Error('Model output contained an unparseable JSON object');
}

interface ChatParams {
  system: string;
  user: string;
  model: string;
  temperature: number;
  jsonMode?: boolean;
  /** Generous default: reasoning models (e.g. openai/gpt-oss) spend budget on
   * hidden reasoning before emitting content — 2048 truncated JSON output. */
  maxTokens?: number;
  apiKeyOverride?: string;
  /** Hard request timeout; the caller falls back to deterministic output. */
  timeoutMs?: number;
}

async function runGroqChat(params: ChatParams): Promise<string> {
  const {
    system,
    user,
    model,
    temperature,
    jsonMode = false,
    maxTokens = 8192,
    apiKeyOverride,
    timeoutMs = 30_000,
  } = params;
  const apiKey = apiKeyOverride || process.env.GROQ_API_KEY;

  if (!apiKey) {
    const err: any = new Error('GROQ_API_KEY is not configured on the server.');
    err.code = 'missing_api_key';
    throw err;
  }

  const client = new Groq({ apiKey, timeout: timeoutMs });

  const completion = await client.chat.completions.create({
    model,
    temperature,
    max_completion_tokens: maxTokens,
    ...(jsonMode ? { response_format: { type: 'json_object' as const } } : {}),
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: user },
    ],
  });

  return completion.choices[0]?.message?.content ?? '';
}

export class GroqService {
  /**
   * Generate a deterministic remediation plan (title + patch + PR body) for a
   * vulnerability. Uses llama-3.3-70b-versatile at temperature 0.2 in JSON mode.
   */
  static async generateRemediation(
    vuln: OSVVulnerability,
    options: { apiKey?: string } = {}
  ): Promise<GroqResult<RemediationResult>> {
    const started = Date.now();

    if (!isGroqConfigured() && !options.apiKey) {
      return {
        success: false,
        error: MISSING_KEY_MESSAGE,
        errorCode: 'missing_api_key',
        httpStatus: 503,
      };
    }

    const apiKey = options.apiKey || process.env.GROQ_API_KEY || '';

    const userPrompt = [
      'Repository vulnerability advisory that must be remediated:',
      JSON.stringify(
        {
          cve: vuln.cveId || vuln.id,
          package: vuln.packageName,
          currentVersion: vuln.currentVersion,
          fixedVersion: vuln.fixedVersion,
          severity: vuln.severity,
          summary: clampAdvisoryText(vuln.summary, 400),
          details: clampAdvisoryText(vuln.details),
          advisoryUrl: vuln.references?.[0]?.url || '',
        },
        null,
        2
      ),
      '',
      'Generate the remediation JSON now.',
    ].join('\n');

    traceGq('remediation', `start package=${vuln.packageName} cve=${vuln.cveId || vuln.id} current=${vuln.currentVersion} fixed=${vuln.fixedVersion}`);
    let usedModel = GROQ_HEAVY_MODEL;
    try {
      let raw: string;
      try {
        traceGq('remediation', `calling ${GROQ_HEAVY_MODEL} (json mode, temp 0.2, 30s timeout)`);
        raw = await runGroqChat({
          system: REMEDIATION_SYSTEM_PROMPT,
          user: userPrompt,
          model: GROQ_HEAVY_MODEL,
          temperature: 0.2,
          jsonMode: true,
          apiKeyOverride: options.apiKey,
        });
      } catch (primaryErr: any) {
        if (!isModelNotFoundError(primaryErr) || !apiKey) throw primaryErr;
        const fallbackModel = await resolveFallbackModel(apiKey, 'heavy');
        if (!fallbackModel) throw primaryErr;
        usedModel = fallbackModel;
        traceGq('remediation', `primary model unavailable -> retrying with ${fallbackModel}`);
        raw = await runGroqChat({
          system: REMEDIATION_SYSTEM_PROMPT,
          user: userPrompt,
          model: fallbackModel,
          temperature: 0.2,
          jsonMode: true,
          apiKeyOverride: options.apiKey,
        });
      }

      let parsed: Record<string, unknown>;
      try {
        parsed = extractJson(raw);
      } catch {
        // Safe fallback: never fail the client - generate the deterministic
        // version bump + standard PR text from the advisory instead.
        traceGq('remediation', `unparseable model output -> deterministic fallback (raw start: ${(raw || '').slice(0, 100).replace(/\s+/g, ' ') || 'empty'})`);
        return buildDeterministicRemediation(vuln, Date.now() - started);
      }

      const fallbackTitle = `fix(security): bump ${vuln.packageName} to ^${vuln.fixedVersion} to resolve ${vuln.cveId || vuln.id}`;
      const fallbackPatch = [
        '--- a/package.json',
        '+++ b/package.json',
        '@@',
        `-  "${vuln.packageName}": "${vuln.currentVersion}"`,
        `+  "${vuln.packageName}": "^${vuln.fixedVersion}"`,
      ].join('\n');
      const fallbackBody = [
        `## Impact`,
        vuln.summary,
        '',
        `## Patch`,
        `Bump \`${vuln.packageName}\` from \`${vuln.currentVersion}\` to \`^${vuln.fixedVersion}\`.`,
        '',
        `## Test Verification`,
        `- [ ] \`npm install\` completes without errors`,
        `- [ ] \`npm audit\` no longer reports ${vuln.cveId || vuln.id}`,
      ].join('\n');

      return {
        success: true,
        title:
          typeof parsed.title === 'string' && parsed.title.trim()
            ? parsed.title.trim()
            : fallbackTitle,
        patch:
          typeof parsed.patch === 'string' && parsed.patch.trim()
            ? parsed.patch.trim()
            : fallbackPatch,
        body:
          typeof parsed.body === 'string' && parsed.body.trim()
            ? parsed.body.trim()
            : fallbackBody,
        model: usedModel,
        provider: 'groq',
        latencyMs: Date.now() - started,
      };
    } catch (err) {
      const structured = toStructuredError(err);
      traceGq('remediation', `failed: ${structured.errorCode} - ${structured.error.slice(0, 140)}`);
      return structured;
    }
  }

  /**
   * Draft celebratory, low-pressure maintainer outreach.
   * Fast task -> llama-3.1-8b-instant.
   */
  static async generateOutreach(
    analysis: Pick<
      ProjectAnalysis,
      'name' | 'owner' | 'repo' | 'repoUrl' | 'milestones' | 'vulnerabilities' | 'fixedDependenciesCount'
    >,
    options: { apiKey?: string } = {}
  ): Promise<GroqResult<OutreachResult>> {
    const started = Date.now();

    if (!isGroqConfigured() && !options.apiKey) {
      return {
        success: false,
        error: MISSING_KEY_MESSAGE,
        errorCode: 'missing_api_key',
        httpStatus: 503,
      };
    }

    const apiKey = options.apiKey || process.env.GROQ_API_KEY || '';

    const vulnLines = analysis.vulnerabilities
      .slice(0, 5)
      .map(
        (v) =>
          `- ${v.packageName} ${v.currentVersion} -> ${v.fixedVersion} (${v.cveId || v.id}, ${v.severity}): ${v.summary}`
      )
      .join('\n');

    const userPrompt = [
      `Project: ${analysis.name} (${analysis.owner}/${analysis.repo})`,
      `Repo: ${analysis.repoUrl}`,
      `GitHub stars: ${analysis.milestones.githubStars}`,
      `Weekly npm downloads: ${analysis.milestones.npmWeeklyDownloads}`,
      `Dependencies fixed by the prepared patch: ${analysis.fixedDependenciesCount}`,
      'Vulnerabilities resolved:',
      vulnLines || '- None (clean audit)',
      '',
      'Generate the outreach JSON now.',
    ].join('\n');

    let usedModel = GROQ_FAST_MODEL;
    try {
      let raw: string;
      try {
        raw = await runGroqChat({
          system: OUTREACH_SYSTEM_PROMPT,
          user: userPrompt,
          model: GROQ_FAST_MODEL,
          temperature: 0.4,
          jsonMode: true,
          apiKeyOverride: options.apiKey,
        });
      } catch (primaryErr: any) {
        if (!isModelNotFoundError(primaryErr) || !apiKey) throw primaryErr;
        const fallbackModel = await resolveFallbackModel(apiKey, 'fast');
        if (!fallbackModel) throw primaryErr;
        usedModel = fallbackModel;
        raw = await runGroqChat({
          system: OUTREACH_SYSTEM_PROMPT,
          user: userPrompt,
          model: fallbackModel,
          temperature: 0.4,
          jsonMode: true,
          apiKeyOverride: options.apiKey,
        });
      }

      let parsed: Record<string, unknown>;
      try {
        parsed = extractJson(raw);
      } catch {
        return {
          success: false,
          error: 'Groq returned an unparseable outreach payload. Please retry.',
          errorCode: 'invalid_response',
          httpStatus: 502,
        };
      }

      const str = (key: string, fallback: string): string =>
        typeof parsed[key] === 'string' && (parsed[key] as string).trim()
          ? (parsed[key] as string).trim()
          : fallback;

      return {
        success: true,
        subject: str('subject', `Security patch proposal for ${analysis.name}`),
        body: str('body', `Hi @${analysis.owner}, we prepared 1-click fixes for ${analysis.name}.`),
        githubIssueTitle: str(
          'githubIssueTitle',
          `Security audit results & 1-click fix proposal for ${analysis.name}`
        ),
        githubIssueMarkdown: str(
          'githubIssueMarkdown',
          `## Security Audit Summary\n\n${vulnLines || 'No vulnerabilities found.'}`
        ),
        prTitle: str(
          'prTitle',
          `fix(security): bump ${analysis.fixedDependenciesCount} dependencies to resolve known CVEs`
        ),
        prBody: str(
          'prBody',
          `This automated PR was generated by RepoShield.\n\n### Vulnerabilities Resolved\n${vulnLines}`
        ),
        model: usedModel,
        provider: 'groq',
        latencyMs: Date.now() - started,
      };
    } catch (err) {
      return toStructuredError(err);
    }
  }
}
