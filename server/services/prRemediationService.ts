/**
 * GitHub Pull Request Remediation Service
 * Implements the fork-and-PR workflow for repositories where direct branch
 * push access is restricted:
 *
 *   1. Verify GITHUB_TOKEN and resolve the authenticated actor.
 *   2. Resolve the target's DEFAULT BRANCH dynamically (never hardcoded).
 *   3. Inspect push permission; fall back to a fork when blocked.
 *   4. Create a UNIQUE fix branch `reposhield/fix-<cve-id>-<timestamp>`
 *      (avoids stale-branch ref conflicts across runs).
 *   5. Wait for the fork to fully materialize (repo + default branch ref).
 *   6. Commit the patched manifest (package.json / lockfile).
 *   7. Open a cross-repository PR (head: `<fork_owner>:<branch>`).
 *
 * Failures return `{ success: false, code, message, logs }` with the exact
 * GitHub HTTP status so the UI can show precise diagnostics.
 *
 * Every call returns structured diagnostics: { success, pr_url?, logs[] } or
 * { success: false, error, logs[] } so the UI can surface exactly what happened.
 */

import { Octokit } from 'octokit';
import type { OSVVulnerability } from '../../src/types/index.ts';

export type PrErrorCode =
  | 'missing_github_token'
  | 'github_api_error'
  | 'missing_token_scope'
  | 'invalid_input';

/** Machine-readable failure payload for the UI. */
export interface PrErrorPayload {
  success: false;
  /** GitHub HTTP status (403, 404, 422...) or 400/500/502/503 for local errors. */
  code: number;
  /** Human-readable diagnostic, e.g. "Missing repo scope on token". */
  message: string;
  logs: PrLogsEntry[];
}

export interface PrLogsEntry {
  step: string;
  status: 'ok' | 'info' | 'error';
  detail: string;
  timestamp: string;
}

export interface PrSuccessResult {
  success: true;
  pr_url: string;
  pr_number: number;
  branch: string;
  mode: 'direct' | 'fork';
  alreadyExisted: boolean;
  logs: PrLogsEntry[];
}

export interface PrFailureResult {
  success: false;
  error: string;
  errorCode: PrErrorCode;
  httpStatus: number;
  /** GitHub HTTP status echoed for the client ({ success, code, message } contract). */
  code?: number;
  /** Raw upstream message, kept separate from the friendlier `error` text. */
  message?: string;
  logs: PrLogsEntry[];
}

export type PrResult = PrSuccessResult | PrFailureResult;

export interface CreateFixPrParams {
  owner: string;
  repo: string;
  vulnerabilities: OSVVulnerability[];
  /** Patched file contents keyed by repo-relative path (e.g. package.json). */
  patchedFiles: Record<string, string>;
  prTitle?: string;
  prBody?: string;
  /** Test hook / user-supplied token; defaults to GITHUB_TOKEN env var. */
  githubTokenOverride?: string;
}

const COMMITTER_NAME = 'RepoShield';
const BRANCH_PREFIX = 'reposhield/fix-';

export function buildFixBranchName(vulnerabilities: OSVVulnerability[]): string {
  const primary = vulnerabilities[0];
  const cveId = (primary?.cveId || primary?.id || 'vulnerability').trim();
  const safe = cveId.toUpperCase().replace(/[^A-Za-z0-9._-]+/g, '-');
  const countSuffix = vulnerabilities.length > 1 ? `-${vulnerabilities.length}cves` : '';
  // Timestamp keeps branches unique per run: re-running the pipeline on the
  // same repo never collides with (or reuses) a stale branch from a prior run.
  const ts = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14); // YYYYMMDDHHMMSS
  return `${BRANCH_PREFIX}${safe}${countSuffix}-${ts}`.slice(0, 200);
}

export function composePrTitle(vulnerabilities: OSVVulnerability[]): string {
  const primary = vulnerabilities[0];
  if (!primary) {
    return 'fix(security): bump vulnerable dependencies to safe versions';
  }
  if (vulnerabilities.length === 1) {
    return `fix(security): bump ${primary.packageName} to ^${primary.fixedVersion} to resolve ${primary.cveId || primary.id}`;
  }
  return `fix(security): bump ${vulnerabilities.length} dependencies to resolve known CVEs`;
}

export function composePrBody(vulnerabilities: OSVVulnerability[]): string {
  const cveLines = vulnerabilities
    .slice(0, 10)
    .map(
      (v) =>
        `- **${v.packageName}** \`${v.currentVersion}\` ➔ \`^${v.fixedVersion}\` — [${v.cveId || v.id}](${v.references?.[0]?.url || 'https://osv.dev'}) (${v.severity})`
    )
    .join('\n');

  return [
    '## Impact',
    `This automated PR resolves ${vulnerabilities.length} known vulnerabilit${vulnerabilities.length === 1 ? 'y' : 'ies'} detected by RepoShield in the dependency manifest.`,
    '',
    '## Vulnerabilities Resolved',
    cveLines,
    '',
    '## Patch',
    'Dependency manifest updated to the minimum patched releases. No breaking API changes within the pinned semver ranges.',
    '',
    '## Test Verification',
    '- [ ] `npm install` completes without errors',
    '- [ ] `npm audit` reports zero known advisories for the bumped packages',
    '- [ ] Test suite passes on the patched dependency set',
    '',
    '---',
    '_Automated remediation drafted by **RepoShield** — review the diff and merge when ready._',
  ].join('\n');
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function logEntry(logs: PrLogsEntry[], step: string, status: PrLogsEntry['status'], detail: string): void {
  logs.push({ step, status, detail, timestamp: new Date().toISOString() });
}

/**
 * Translate a GitHub API failure into a precise, human-readable diagnostic.
 * 403 after auth  -> token lacks `repo`/push scope (most common external-repo failure)
 * 404 after auth  -> repo does not exist, is private, or is invisible to the token
 * 422 on PR create -> head/base invalid (fork not ready) or PR already exists
 */
function humanizeGitHubError(err: any, context: string): string {
  const status = err?.status;
  const raw = String(err?.message || 'Unknown GitHub API failure.');
  if (status === 403) {
    if (/rate limit/i.test(raw)) {
      return context + ': GitHub API rate limit exhausted for this token. Wait for the limit window to reset.';
    }
    return context + ': token lacks permission for this operation (missing `repo` scope on the classic PAT, or fine-grained PAT without contents:write for this repository).';
  }
  if (status === 404) {
    return context + ': repository not found - it may be private, renamed, or invisible to this token.';
  }
  if (status === 422) {
    return context + ': request rejected (branch/ref conflict or PR already exists). ' + raw;
  }
  return context + ': ' + raw;
}

function trace(step: string, detail: string): void {
  console.log(`[pr-remediation] ${step}: ${detail}`);
}

/**
 * Ensure a ready fork exists under `login`. Resolved lazily because push
 * access can be denied at two levels: the repo `permissions.push` flag, or
 * the token itself (fine-grained PATs without Contents:write 403 on ref
 * creation even when permissions.push is true).
 */
async function ensureForkBefore(
  octokit: Octokit,
  owner: string,
  repo: string,
  login: string,
  defaultBranch: string,
  logs: PrLogsEntry[],
  reason: string
): Promise<{ ready: boolean; fatal?: boolean; message?: string }> {
  trace('fork', `forking ${owner}/${repo} under ${login} (${reason})`);
  logEntry(logs, 'fork', 'info', `Creating fork of ${owner}/${repo} for ${login} (${reason})...`);
  try {
    await octokit.rest.repos.createFork({ owner, repo });
  } catch (forkErr: any) {
    // 202 Accepted is normal. A 403 is a real denial only if no fork exists;
    // otherwise the fork may already be present, so keep polling.
    if (forkErr?.status === 403) {
      try {
        const probe = await octokit.rest.repos.get({ owner: login, repo });
        if (!probe.data.fork) {
          const detail =
            `Token is not allowed to fork ${owner}/${repo} (HTTP 403). ` +
            `Fine-grained personal access tokens must (1) include the target repository or select "All repositories", ` +
            `(2) grant "Contents: Read and write" and "Administration: Read and write" permissions, ` +
            `or use a classic token with the "repo" scope.`;
          logEntry(logs, 'fork', 'error', detail);
          trace('fork', `denied: ${detail}`);
          return { ready: false, fatal: true, message: detail };
        }
        logEntry(logs, 'fork', 'info', `Fork API responded 403 but fork ${login}/${repo} already exists; continuing.`);
      } catch (probeErr: any) {
        if (probeErr?.status === 404) {
          const detail =
            `Token is not allowed to fork ${owner}/${repo} (HTTP 403) and no fork exists yet. ` +
            `Fine-grained personal access tokens must include the target repository (or "All repositories") and grant "Administration: Read and write", or use a classic token with the "repo" scope.`;
          logEntry(logs, 'fork', 'error', detail);
          trace('fork', `denied: ${detail}`);
          return { ready: false, fatal: true, message: detail };
        }
        logEntry(logs, 'fork', 'info', `Fork API responded 403; probe errored (${probeErr?.status}); continuing to poll.`);
      }
    } else if (forkErr?.status && forkErr.status !== 202) {
      logEntry(logs, 'fork', 'info', `Fork API responded ${forkErr.status}; continuing (fork may already exist).`);
    }
  }

  // Fork readiness = repo exists AND the default branch ref is present.
  // Checking only `fork: true` caused intermittent ref errors when the
  // git data had not finished copying yet.
  for (let attempt = 0; attempt < 20; attempt++) {
    await sleep(1500);
    try {
      const forkInfo = await octokit.rest.repos.get({ owner: login, repo });
      if (!forkInfo.data.fork) continue;
      try {
        await octokit.rest.git.getRef({
          owner: login,
          repo,
          ref: `heads/${defaultBranch}`,
        });
        trace('fork', `ready at ${login}/${repo}`);
        logEntry(logs, 'fork', 'ok', `Fork ready at ${login}/${repo}.`);
        return { ready: true };
      } catch {
        // Repo exists but git refs not copied yet; keep polling.
      }
    } catch {
      // Fork still materializing; retry.
    }
  }
  const detail = `Fork of ${owner}/${repo} did not become ready within the 30s wait window (GitHub forks can take minutes for large repositories). Retry shortly.`;
  logEntry(logs, 'fork', 'error', detail);
  trace('fork', 'not ready within wait window');
  return { ready: false, message: detail };
}

export class PrRemediationService {
  static async createFixPullRequest(params: CreateFixPrParams): Promise<PrResult> {
    const { owner, repo, vulnerabilities, patchedFiles, prTitle, prBody, githubTokenOverride } = params;
    const logs: PrLogsEntry[] = [];

    const token = (githubTokenOverride ?? process.env.GITHUB_TOKEN ?? '').trim();
    if (!token) {
      logEntry(logs, 'auth', 'error', 'GITHUB_TOKEN is not configured on the server.');
      trace('auth', 'GITHUB_TOKEN missing on server');
      return {
        success: false,
        error:
          'GITHUB_TOKEN is not configured on the server. Set GITHUB_TOKEN (classic PAT with `repo` scope) to enable automated fix pull requests.',
        errorCode: 'missing_github_token',
        httpStatus: 503,
        code: 503,
        message: 'GITHUB_TOKEN is not configured on the server.',
        logs,
      };
    }

    if (!owner || !repo) {
      logEntry(logs, 'validate', 'error', 'Repository owner/name missing from request.');
      trace('validate', 'owner/repo missing from request');
      return {
        success: false,
        error: 'Repository owner and name are required to create a fix pull request.',
        errorCode: 'invalid_input',
        httpStatus: 400,
        code: 400,
        message: 'Repository owner and name are required.',
        logs,
      };
    }

    const filePaths = Object.keys(patchedFiles);
    if (filePaths.length === 0) {
      logEntry(logs, 'validate', 'error', 'No patched file contents supplied.');
      trace('validate', 'no patched files supplied');
      return {
        success: false,
        error: 'No patched file contents were supplied for the fix commit.',
        errorCode: 'invalid_input',
        httpStatus: 400,
        code: 400,
        message: 'No patched file contents were supplied for the fix commit.',
        logs,
      };
    }

    const octokit = new Octokit({ auth: token });
    const branchName = buildFixBranchName(vulnerabilities);

    try {
      // 1. Identify the authenticated actor + their permission on the upstream repo.
      const me = await octokit.rest.users.getAuthenticated();
      logEntry(logs, 'auth', 'ok', `Authenticated as ${me.data.login}.`);

      const repoInfo = await octokit.rest.repos.get({ owner, repo });
      // Dynamic default branch resolution - never assume 'main'.
      const defaultBranch = repoInfo.data.default_branch || 'main';
      const canPushDirectly = Boolean((repoInfo.data as any).permissions?.push);
      trace('permission-check', `target=${owner}/${repo} base=${defaultBranch} push=${canPushDirectly}`);
      logEntry(
        logs,
        'permission-check',
        'ok',
        `${owner}/${repo} default branch is "${defaultBranch}". Push access: ${canPushDirectly ? 'granted' : 'denied'}${canPushDirectly ? '' : ' -> will fork'}.`
      );

      // 2. Resolve commit target: upstream repo when we have push access, else our fork.
      let commitOwner = owner;
      let mode: 'direct' | 'fork' = 'direct';
      if (!canPushDirectly) {
        const fork = await ensureForkBefore(octokit, owner, repo, me.data.login, defaultBranch, logs, 'no push access to upstream');
        if (!fork.ready) {
          return {
            success: false,
            error: fork.message || 'Fork did not become ready in time.',
            errorCode: fork.fatal ? 'missing_token_scope' : 'github_api_error',
            httpStatus: fork.fatal ? 403 : 502,
            code: fork.fatal ? 403 : 502,
            message: fork.fatal ? 'Token lacks fork permission - update the GitHub token scopes (see error detail).' : 'Fork in progress - GitHub did not finish copying the repository in time. Retry shortly.',
            logs,
          };
        }
        commitOwner = me.data.login;
        mode = 'fork';
      }

      // 3. Grab the base SHA of the default branch to seed the fix branch from.
      const baseRef = await octokit.rest.git.getRef({
        owner: commitOwner,
        repo,
        ref: `heads/${defaultBranch}`,
      });
      const baseSha = baseRef.data.object.sha;

      // 4. Create (or reuse) the fix branch.
      let branchRef;
      try {
        branchRef = await octokit.rest.git.getRef({
          owner: commitOwner,
          repo,
          ref: `heads/${branchName}`,
        });
        logEntry(logs, 'branch', 'info', `Branch ${branchName} already exists; reusing it.`);
      } catch {
        try {
          branchRef = await octokit.rest.git.createRef({
            owner: commitOwner,
            repo,
            ref: `refs/heads/${branchName}`,
            sha: baseSha,
          });
          logEntry(logs, 'branch', 'ok', `Created branch ${branchName} from ${defaultBranch} (${baseSha.slice(0, 7)}).`);
        } catch (refErr: any) {
          // permissions.push can be true while the token still lacks write
          // access (fine-grained PATs without Contents:write). Degrade to the
          // fork path instead of failing the run.
          if (refErr?.status !== 403 || mode === 'fork') throw refErr;
          trace('branch', `createRef 403 on ${owner}/${repo} -> degrading to fork path`);
          logEntry(logs, 'branch', 'info', `Direct branch creation denied (HTTP 403) on ${owner}/${repo}; falling back to fork workflow.`);
          const fork = await ensureForkBefore(octokit, owner, repo, me.data.login, defaultBranch, logs, 'direct branch creation denied (token lacks write access)');
          if (!fork.ready) {
            return {
              success: false,
              error: fork.message || 'Fork did not become ready in time.',
              errorCode: fork.fatal ? 'missing_token_scope' : 'github_api_error',
              httpStatus: fork.fatal ? 403 : 502,
              code: fork.fatal ? 403 : 502,
              message: fork.fatal ? 'Token lacks fork permission - update the GitHub token scopes (see error detail).' : 'Fork in progress - GitHub did not finish copying the repository in time. Retry shortly.',
              logs,
            };
          }
          commitOwner = me.data.login;
          mode = 'fork';
          const forkBaseRef = await octokit.rest.git.getRef({
            owner: commitOwner,
            repo,
            ref: `heads/${defaultBranch}`,
          });
          branchRef = await octokit.rest.git.createRef({
            owner: commitOwner,
            repo,
            ref: `refs/heads/${branchName}`,
            sha: forkBaseRef.data.object.sha,
          });
          logEntry(logs, 'branch', 'ok', `Created branch ${branchName} on fork ${commitOwner}/${repo}.`);
        }
      }

      // 5. Commit each patched file onto the fix branch.
      const committed: string[] = [];
      for (const path of filePaths) {
        const content = patchedFiles[path];
        let existingSha: string | undefined;
        try {
          const existing = await octokit.rest.repos.getContent({
            owner: commitOwner,
            repo,
            path,
            ref: branchName,
          });
          if (!Array.isArray(existing.data) && 'sha' in existing.data) {
            existingSha = existing.data.sha;
          }
        } catch {
          logEntry(logs, 'commit', 'info', `${path} not present on branch; creating it.`);
        }

        await octokit.rest.repos.createOrUpdateFileContents({
          owner: commitOwner,
          repo,
          path,
          branch: branchName,
          message: prTitle || composePrTitle(vulnerabilities),
          content: Buffer.from(content, 'utf8').toString('base64'),
          ...(existingSha ? { sha: existingSha } : {}),
        });
        committed.push(path);
        logEntry(logs, 'commit', 'ok', `Committed patched ${path} to ${branchName}.`);
      }

      // 6. Open the pull request against the upstream default branch.
      const head = mode === 'fork' ? `${commitOwner}:${branchName}` : branchName;
      const title = prTitle || composePrTitle(vulnerabilities);
      const body =
        prBody ||
        composePrBody(vulnerabilities) +
          (mode === 'fork'
            ? `\n\n_Patch applied via the [${commitOwner}/${repo}](${`https://github.com/${commitOwner}/${repo}`}) fork (no direct push access)._`
            : '');

      try {
        const pr = await octokit.rest.pulls.create({
          owner,
          repo,
          head,
          base: defaultBranch,
          title,
          body,
        });
        logEntry(logs, 'pull-request', 'ok', `Pull request #${pr.data.number} opened: ${pr.data.html_url}`);
        return {
          success: true,
          pr_url: pr.data.html_url,
          pr_number: pr.data.number,
          branch: branchName,
          mode,
          alreadyExisted: false,
          logs,
        };
      } catch (prErr: any) {
        // 422 -> a PR for this head/base pair may already be open. Return it idempotently.
        if (prErr?.status === 422) {
          const existing = await octokit.rest.pulls.list({
            owner,
            repo,
            head: mode === 'fork' ? `${commitOwner}:${branchName}` : `${owner}:${branchName}`,
            base: defaultBranch,
            state: 'open',
          });
          const match = existing.data.find((p) => p.head.ref === branchName);
          if (match) {
            logEntry(logs, 'pull-request', 'info', `Pull request already open: ${match.html_url}`);
            return {
              success: true,
              pr_url: match.html_url,
              pr_number: match.number,
              branch: branchName,
              mode,
              alreadyExisted: true,
              logs,
            };
          }
        }
        throw prErr;
      }
    } catch (err: any) {
      const status: number = err?.status ?? 500;
      const upstreamMessage: string = err?.message || 'Failed to create fix pull request.';
      trace('error', `HTTP ${status}: ${upstreamMessage}`);
      logEntry(logs, 'error', 'error', upstreamMessage);

      // Map raw GitHub statuses into human-readable diagnostics so the UI can
      // show "Missing repo scope on token" instead of a bare 403.
      let friendly = `GitHub API error (HTTP ${status}): ${upstreamMessage}`;
      if (status === 403 && /resource not accessible|not allowed|forbidden/i.test(upstreamMessage)) {
        friendly = `Missing repo scope on token (HTTP 403): the GITHUB_TOKEN needs the 'repo' (or 'public_repo') scope to fork and open pull requests on ${owner}/${repo}. ${upstreamMessage}`;
      } else if (status === 404) {
        friendly = `Repository ${owner}/${repo} not found or token cannot see it (HTTP 404). Check the repo name and token access. ${upstreamMessage}`;
      } else if (status === 401) {
        friendly = `GitHub rejected the token (HTTP 401): it is expired or revoked. ${upstreamMessage}`;
      } else if (status === 422) {
        friendly = `GitHub rejected the pull request (HTTP 422): ${upstreamMessage}`;
      }

      return {
        success: false,
        error: friendly,
        code: status,
        message: upstreamMessage,
        errorCode: 'github_api_error',
        httpStatus: status >= 400 && status < 600 ? status : 502,
        logs,
      };
    }
  }
}
