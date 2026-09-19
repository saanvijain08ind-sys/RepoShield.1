/**
 * GitHub Pull Request Remediation Service
 * Implements the fork-and-PR workflow for repositories where direct branch
 * push access is restricted:
 *
 *   1. Verify GITHUB_TOKEN and resolve the authenticated actor.
 *   2. Inspect upstream push permission; fall back to a fork when blocked.
 *   3. Create fix branch `reposhield/fix-<cve-id>` from the default branch.
 *   4. Commit the patched dependency file (package.json / lockfile).
 *   5. Open a pull request against the repository default branch.
 *
 * Every call returns structured diagnostics: { success, pr_url?, logs[] } or
 * { success: false, error, logs[] } so the UI can surface exactly what happened.
 */

import { Octokit } from 'octokit';
import type { OSVVulnerability } from '../../src/types/index.ts';

export type PrErrorCode =
  | 'missing_github_token'
  | 'github_api_error'
  | 'invalid_input';

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
  const suffix = vulnerabilities.length > 1 ? `-${vulnerabilities.length}-cves` : '';
  return `${BRANCH_PREFIX}${safe}${suffix}`.slice(0, 200);
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

export class PrRemediationService {
  static async createFixPullRequest(params: CreateFixPrParams): Promise<PrResult> {
    const { owner, repo, vulnerabilities, patchedFiles, prTitle, prBody, githubTokenOverride } = params;
    const logs: PrLogsEntry[] = [];

    const token = (githubTokenOverride ?? process.env.GITHUB_TOKEN ?? '').trim();
    if (!token) {
      logEntry(logs, 'auth', 'error', 'GITHUB_TOKEN is not configured on the server.');
      return {
        success: false,
        error:
          'GITHUB_TOKEN is not configured on the server. Set GITHUB_TOKEN (classic PAT with `repo` scope) to enable automated fix pull requests.',
        errorCode: 'missing_github_token',
        httpStatus: 503,
        logs,
      };
    }

    if (!owner || !repo) {
      logEntry(logs, 'validate', 'error', 'Repository owner/name missing from request.');
      return {
        success: false,
        error: 'Repository owner and name are required to create a fix pull request.',
        errorCode: 'invalid_input',
        httpStatus: 400,
        logs,
      };
    }

    const filePaths = Object.keys(patchedFiles);
    if (filePaths.length === 0) {
      logEntry(logs, 'validate', 'error', 'No patched file contents supplied.');
      return {
        success: false,
        error: 'No patched file contents were supplied for the fix commit.',
        errorCode: 'invalid_input',
        httpStatus: 400,
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
      const defaultBranch = repoInfo.data.default_branch || 'main';
      const canPushDirectly = Boolean((repoInfo.data as any).permissions?.push);
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
        logEntry(logs, 'fork', 'info', `Creating fork of ${owner}/${repo} for ${me.data.login}...`);
        try {
          await octokit.rest.repos.createFork({ owner, repo });
        } catch (forkErr: any) {
          // 202 Accepted is normal; real failures surface below during polling.
          if (forkErr?.status && forkErr.status !== 202) {
            logEntry(logs, 'fork', 'info', `Fork API responded ${forkErr.status}; continuing (fork may already exist).`);
          }
        }

        let forkReady = false;
        for (let attempt = 0; attempt < 12 && !forkReady; attempt++) {
          await sleep(1500);
          try {
            const forkInfo = await octokit.rest.repos.get({ owner: me.data.login, repo });
            forkReady = Boolean(forkInfo.data.fork);
          } catch {
            // Fork still materializing; retry.
          }
        }
        if (!forkReady) {
          logEntry(logs, 'fork', 'error', 'Fork did not become ready within the wait window.');
          return {
            success: false,
            error: `Fork of ${owner}/${repo} did not become ready in time. Try again shortly.`,
            errorCode: 'github_api_error',
            httpStatus: 502,
            logs,
          };
        }
        commitOwner = me.data.login;
        mode = 'fork';
        logEntry(logs, 'fork', 'ok', `Fork ready at ${commitOwner}/${repo}.`);
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
        branchRef = await octokit.rest.git.createRef({
          owner: commitOwner,
          repo,
          ref: `refs/heads/${branchName}`,
          sha: baseSha,
        });
        logEntry(logs, 'branch', 'ok', `Created branch ${branchName} from ${defaultBranch} (${baseSha.slice(0, 7)}).`);
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
            head: mode === 'fork' ? `${owner}:${branchName}`.replace(`${owner}:`, `${commitOwner}:`) : `${owner}:${branchName}`,
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
      logEntry(logs, 'error', 'error', err?.message || 'Unknown GitHub API failure.');
      return {
        success: false,
        error: `GitHub API error (HTTP ${status}): ${err?.message || 'Failed to create fix pull request.'}`,
        errorCode: 'github_api_error',
        httpStatus: status >= 400 && status < 600 ? status : 502,
        logs,
      };
    }
  }
}
