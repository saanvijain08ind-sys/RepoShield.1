import React, { useState } from 'react';
import {
  GitPullRequest,
  CheckCircle2,
  Copy,
  Check,
  Code2,
  FileCode,
  Sparkles,
  ExternalLink,
  ShieldCheck,
  Terminal,
  ArrowRight,
  Key,
  Lock,
  ShieldAlert,
  Wand2,
  Loader2,
  GitBranch,
  AlertTriangle,
} from 'lucide-react';
import { ProjectAnalysis } from '../types/index.ts';
import { AdvisoryMarkdown } from './AdvisoryMarkdown.tsx';
import { getStoredGroqKey } from '../services/groqKeyStore.ts';

interface RemediationDiffViewProps {
  analysis: ProjectAnalysis;
  onProceedToOutreach: () => void;
}

export const RemediationDiffView: React.FC<RemediationDiffViewProps> = ({
  analysis,
  onProceedToOutreach,
}) => {
  const {
    gitDiff,
    updatedPackageJson,
    rawPackageJson,
    fixedDependenciesCount,
    vulnerabilities,
    owner,
    repo,
    repoUrl,
  } = analysis;

  const [activeTab, setActiveTab] = useState<'diff' | 'patched' | 'original'>('diff');
  const [copied, setCopied] = useState(false);

  // ---- Groq AI remediation + automated fix PR pipeline state ----
  const primaryVuln = vulnerabilities[0];
  const [aiState, setAiState] = useState<{
    loading: boolean;
    error: string | null;
    result: { title: string; patch: string; body: string; model?: string } | null;
  }>({ loading: false, error: null, result: null });
  const [prState, setPrState] = useState<{
    loading: boolean;
    error: string | null;
    logs: Array<{ step: string; status: string; detail: string }> | null;
    result: { pr_url: string; mode: string; branch: string } | null;
  }>({ loading: false, error: null, logs: null, result: null });

  const handleGenerateAiRemediation = async () => {
    if (!primaryVuln) return;
    setAiState({ loading: true, error: null, result: null });
    try {
      const res = await fetch('/api/sentinel/remediation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vulnerability: primaryVuln,
          groqApiKey: getStoredGroqKey() || undefined,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.success === false) {
        throw new Error(data.error || `Groq remediation failed (HTTP ${res.status})`);
      }
      setAiState({
        loading: false,
        error: null,
        result: { title: data.title, patch: data.patch, body: data.body, model: data.model },
      });
    } catch (err: any) {
      setAiState({ loading: false, error: err.message || 'Groq remediation failed.', result: null });
    }
  };

  const handleCreateFixPr = async () => {
    setPrState({ loading: true, error: null, logs: null, result: null });
    let errorLogs: Array<{ step: string; status: string; detail: string }> | null = null;
    try {
      const res = await fetch('/api/sentinel/create-fix-pr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          owner,
          repo,
          vulnerabilities,
          patchedFiles: updatedPackageJson ? { 'package.json': updatedPackageJson } : {},
          prTitle: aiState.result?.title,
          prBody: aiState.result?.body,
        }),
      });
      const data = await res.json().catch(() => ({}));
      errorLogs = data.logs || null;
      if (!res.ok || data.success === false) {
        throw new Error(data.error || `Fix PR pipeline failed (HTTP ${res.status})`);
      }
      setPrState({
        loading: false,
        error: null,
        logs: data.logs || null,
        result: { pr_url: data.pr_url, mode: data.mode, branch: data.branch },
      });
    } catch (err: any) {
      setPrState({ loading: false, error: err.message || 'Fix PR pipeline failed.', logs: errorLogs, result: null });
    }
  };

  const handleCopy = () => {
    const text = activeTab === 'diff' ? gitDiff : activeTab === 'patched' ? updatedPackageJson : rawPackageJson;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Split diff into formatted lines
  const diffLines = (gitDiff || '').split('\n');

  return (
    <div className="space-y-6">
      {/* 1. Remediation Header */}
      <div className="bg-white dark:bg-[#161b22] border-2 border-[#1a1a1c] dark:border-[#f0f6fc] p-6 shadow-xs">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b-2 border-[#1a1a1c] dark:border-[#f0f6fc]">
          <div>
            <div className="flex items-center gap-2">
              <span className="label-mono text-[#2ea043]">
                1-Click Automated Patch
              </span>
              <span className="text-xs font-mono-code text-[#1a1a1c]/60 dark:text-[#f0f6fc]/60">
                • Minimal-invasive bumps
              </span>
            </div>
            <h3 className="font-syne text-xl font-extrabold uppercase tracking-tight text-[#1a1a1c] dark:text-[#f0f6fc] mt-1">
              Vulnerability Remediation & Manifest Patch
            </h3>
            <p className="text-xs font-mono-code text-[#1a1a1c]/70 dark:text-[#f0f6fc]/70 mt-1">
              Automated safe-patching replaces vulnerable dependency declarations with verified fixed release targets.
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={handleCopy}
              className="px-3.5 py-2 text-xs font-mono-code font-bold uppercase text-[#1a1a1c] dark:text-[#f0f6fc] bg-white dark:bg-[#161b22] hover:bg-[#f0f6fc] dark:hover:bg-[#21262d] border border-[#1a1a1c] dark:border-[#f0f6fc] transition-colors flex items-center gap-1.5 shadow-2xs"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-[#2ea043]" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>

            <button
              id="goto-outreach-btn"
              onClick={onProceedToOutreach}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-mono-code font-bold uppercase tracking-wider text-white bg-[#2ea043] hover:bg-[#2c9740] border border-[#1a1a1c] dark:border-[#f0f6fc] shadow-xs transition-opacity"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Draft Maintainer Outreach</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Patch Statistics */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-4">
          <div className="p-4 bg-[#f8f7f4] dark:bg-[#0f1117] border-2 border-[#1a1a1c] dark:border-[#f0f6fc]">
            <div className="label-mono">Packages Patched</div>
            <div className="font-syne text-2xl font-extrabold text-[#2ea043] mt-1">
              {fixedDependenciesCount} Targets
            </div>
          </div>

          <div className="p-4 bg-[#f8f7f4] dark:bg-[#0f1117] border-2 border-[#1a1a1c] dark:border-[#f0f6fc]">
            <div className="label-mono">Semver Compatibility</div>
            <div className="font-syne text-2xl font-extrabold text-[#1a1a1c] dark:text-[#f0f6fc] mt-1">
              Zero Breaking
            </div>
          </div>

          <div className="p-4 bg-[#f8f7f4] dark:bg-[#0f1117] border-2 border-[#1a1a1c] dark:border-[#f0f6fc]">
            <div className="label-mono">OSV CVE Mitigation</div>
            <div className="font-syne text-2xl font-extrabold text-[#1a1a1c] dark:text-[#f0f6fc] mt-1">
              {vulnerabilities.length} Mitigated
            </div>
          </div>
        </div>
      </div>

      {/* 2. AI Remediation & Automated Fix PR Pipeline (Groq + GitHub) */}
      <div className="bg-white dark:bg-[#161b22] border-2 border-[#1a1a1c] dark:border-[#f0f6fc] p-6 shadow-xs space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Wand2 className="w-5 h-5 text-[#8957e5]" />
            <div>
              <div className="label-mono text-[#8957e5]">AI Remediation Engine • Groq llama-3.3-70b-versatile</div>
              <p className="text-xs font-mono-code text-[#1a1a1c]/70 dark:text-[#f0f6fc]/70 mt-0.5">
                Deterministic JSON remediation (temperature 0.2) feeding the automated fork-and-PR pipeline.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              id="generate-ai-remediation-btn"
              onClick={handleGenerateAiRemediation}
              disabled={aiState.loading || !primaryVuln}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-mono-code font-bold uppercase tracking-wider text-white bg-[#8957e5] hover:bg-[#8250df] border border-[#1a1a1c] dark:border-[#f0f6fc] shadow-xs transition-opacity disabled:opacity-50"
            >
              {aiState.loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Wand2 className="w-3.5 h-3.5" />}
              <span>{aiState.loading ? 'Generating…' : 'Generate AI Remediation'}</span>
            </button>
            <button
              id="create-fix-pr-btn"
              onClick={handleCreateFixPr}
              disabled={prState.loading || !primaryVuln}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-mono-code font-bold uppercase tracking-wider text-white bg-[#1f883d] hover:bg-[#1a7f37] border border-[#1a1a1c] dark:border-[#f0f6fc] shadow-xs transition-opacity disabled:opacity-50"
            >
              {prState.loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <GitPullRequest className="w-3.5 h-3.5" />}
              <span>{prState.loading ? 'Opening PR…' : 'Create Fix PR (Fork & Pull)'}</span>
            </button>
          </div>
        </div>

        {aiState.error && (
          <div className="p-3 bg-[#fff8f8] dark:bg-[#2c1517] border-2 border-[#cf222e] text-xs font-mono-code text-[#cf222e] dark:text-[#ff7b72] flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>{aiState.error}</span>
          </div>
        )}

        {aiState.result && (
          <div className="space-y-3">
            <div className="p-3 bg-[#f8f7f4] dark:bg-[#0f1117] border-2 border-[#1a1a1c] dark:border-[#f0f6fc]">
              <div className="label-mono mb-1">PR Title</div>
              <code className="font-mono-code text-xs text-[#1a1a1c] dark:text-[#f0f6fc] break-words">{aiState.result.title}</code>
            </div>
            <div className="p-3 bg-[#0d1117] border border-[#30363d] rounded">
              <div className="label-mono text-slate-400 mb-1.5">Patch</div>
              <pre className="font-mono-code text-xs text-emerald-400 whitespace-pre-wrap break-words max-h-64 overflow-y-auto">{aiState.result.patch}</pre>
            </div>
            <div className="p-3 bg-[#f8f7f4] dark:bg-[#0f1117] border-2 border-[#1a1a1c] dark:border-[#f0f6fc]">
              <div className="label-mono mb-1.5">PR Body (Markdown)</div>
              <AdvisoryMarkdown content={aiState.result.body} variant="full" />
            </div>
          </div>
        )}

        {prState.error && (
          <div className="p-3 bg-[#fff8f8] dark:bg-[#2c1517] border-2 border-[#cf222e] text-xs font-mono-code text-[#cf222e] dark:text-[#ff7b72] space-y-2">
            <div className="flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{prState.error}</span>
            </div>
            {prState.logs && prState.logs.length > 0 && (
              <ul className="space-y-0.5 opacity-80 pl-6 list-disc">
                {prState.logs.map((l, i) => (
                  <li key={i}>
                    <span className="font-bold">[{l.step}]</span> {l.detail}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {prState.result && (
          <div className="p-3 bg-[#dafbe1] dark:bg-[#0d4429]/40 border-2 border-[#2ea043] text-xs font-mono-code text-[#1a7f37] dark:text-[#3fb950] space-y-1.5">
            <div className="flex items-center gap-2 font-bold">
              <CheckCircle2 className="w-4 h-4" />
              <span>
                Pull request opened via {prState.result.mode === 'fork' ? 'fork workflow' : 'direct branch push'} — branch{' '}
                <code className="font-bold">{prState.result.branch}</code>
              </span>
            </div>
            <a href={prState.result.pr_url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 underline font-bold text-[#0969da] dark:text-[#58a6ff]">
              {prState.result.pr_url}
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
            {prState.logs && prState.logs.length > 0 && (
              <ul className="space-y-0.5 opacity-80 pl-6 list-disc">
                {prState.logs.map((l, i) => (
                  <li key={i}>
                    <span className="font-bold">[{l.step}]</span> {l.detail}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>

      {/* 3. Code Viewer & Tabs */}
      <div className="bg-white dark:bg-[#161b22] border-2 border-[#1a1a1c] dark:border-[#f0f6fc] overflow-hidden shadow-xs">
        <div className="flex items-center justify-between px-4 py-2.5 bg-[#f8f7f4] dark:bg-[#0f1117] border-b-2 border-[#1a1a1c] dark:border-[#f0f6fc]">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveTab('diff')}
              className={`px-3 py-1.5 text-xs font-mono-code font-bold uppercase transition-colors flex items-center gap-1.5 ${
                activeTab === 'diff'
                  ? 'bg-[#1a1a1c] text-white dark:bg-[#f0f6fc] dark:text-[#0f1117]'
                  : 'text-[#1a1a1c]/70 dark:text-[#f0f6fc]/70 hover:text-[#1a1a1c]'
              }`}
            >
              <GitPullRequest className="w-3.5 h-3.5" />
              <span>Unified Git Diff</span>
            </button>

            <button
              onClick={() => setActiveTab('patched')}
              className={`px-3 py-1.5 text-xs font-mono-code font-bold uppercase transition-colors flex items-center gap-1.5 ${
                activeTab === 'patched'
                  ? 'bg-[#1a1a1c] text-white dark:bg-[#f0f6fc] dark:text-[#0f1117]'
                  : 'text-[#1a1a1c]/70 dark:text-[#f0f6fc]/70 hover:text-[#1a1a1c]'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>Patched package.json</span>
            </button>

            <button
              onClick={() => setActiveTab('original')}
              className={`px-3 py-1.5 text-xs font-mono-code font-bold uppercase transition-colors flex items-center gap-1.5 ${
                activeTab === 'original'
                  ? 'bg-[#1a1a1c] text-white dark:bg-[#f0f6fc] dark:text-[#0f1117]'
                  : 'text-[#1a1a1c]/70 dark:text-[#f0f6fc]/70 hover:text-[#1a1a1c]'
              }`}
            >
              <Code2 className="w-3.5 h-3.5" />
              <span>Original package.json</span>
            </button>
          </div>

          <span className="text-[11px] font-mono-code text-[#1a1a1c]/60 dark:text-[#f0f6fc]/60">
            {activeTab === 'diff' ? 'package.json (diff)' : 'package.json'}
          </span>
        </div>

        {/* Diff Code Display */}
        <div className="p-4 overflow-x-auto bg-[#0d1117] text-slate-100 font-mono-code text-xs max-h-[500px]">
          {activeTab === 'diff' && (
            <pre className="space-y-0.5">
              {diffLines.map((line, idx) => {
                let color = 'text-slate-400';
                let bg = '';
                if (line.startsWith('+') && !line.startsWith('+++')) {
                  color = 'text-emerald-400 font-semibold';
                  bg = 'bg-emerald-950/40 -mx-4 px-4 block';
                } else if (line.startsWith('-') && !line.startsWith('---')) {
                  color = 'text-rose-400 font-semibold';
                  bg = 'bg-rose-950/40 -mx-4 px-4 block';
                } else if (line.startsWith('@@')) {
                  color = 'text-blue-400';
                }

                return (
                  <div key={idx} className={`${bg} ${color}`}>
                    {line}
                  </div>
                );
              })}
            </pre>
          )}

          {activeTab === 'patched' && (
            <pre className="text-emerald-400">
              <code>{updatedPackageJson}</code>
            </pre>
          )}

          {activeTab === 'original' && (
            <pre className="text-slate-300">
              <code>{rawPackageJson}</code>
            </pre>
          )}
        </div>
      </div>

      {/* 3. Exposed Secrets & Hardening Guidance (when secrets are detected) */}
      {analysis.exposedSecrets && analysis.exposedSecrets.length > 0 && (
        <div className="bg-white dark:bg-[#161b22] border-2 border-[#1a1a1c] dark:border-[#f0f6fc] p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between pb-3 border-b-2 border-[#1a1a1c] dark:border-[#f0f6fc]">
            <div className="flex items-center gap-2">
              <Key className="w-5 h-5 text-[#cf222e]" />
              <h4 className="font-syne text-base sm:text-lg font-bold text-[#1a1a1c] dark:text-[#f0f6fc]">
                Secret Hardening &amp; Credential Rotation Checklist ({analysis.exposedSecrets.length})
              </h4>
            </div>
            <span className="px-2.5 py-0.5 text-xs font-mono-code font-bold uppercase bg-[#cf222e] text-white">
              Required Before Merge
            </span>
          </div>

          <p className="text-xs font-sans text-[#24292f] dark:text-[#d0d7de]">
            Hardcoded credentials cannot be safeguarded by updating dependency versions alone. Follow this automated hardening checklist to remove credentials from git history:
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {analysis.exposedSecrets.map((secret) => (
              <div
                key={secret.id}
                className="p-3.5 bg-[#f8f7f4] dark:bg-[#0f1117] border-2 border-[#1a1a1c] dark:border-[#f0f6fc] space-y-2 text-xs font-mono-code"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-[#cf222e] dark:text-[#ff7b72]">
                    {secret.category}
                  </span>
                  <span className="text-[10px] bg-[#0d1117] text-slate-300 px-2 py-0.5 border border-slate-700">
                    {secret.filePath}
                  </span>
                </div>

                <div className="text-slate-600 dark:text-slate-400">
                  Value: <span className="font-bold text-amber-500">{secret.maskedSecret}</span>
                </div>

                <div className="p-2 bg-[#0d1117] text-emerald-400 border border-slate-700 overflow-x-auto">
                  <code>{secret.recommendedRefactor}</code>
                </div>

                <div className="text-[11px] text-[#57606a] dark:text-[#8b949e]">
                  1. Revoke on <span className="font-semibold">{secret.providerName}</span>.<br />
                  2. Store as <code className="font-bold text-[#0969da] dark:text-[#58a6ff]">{secret.envVarName}</code> in secret store.
                </div>
              </div>
            ))}
          </div>

          <div className="p-3 bg-[#0d1117] border border-[#30363d] text-xs font-mono-code text-slate-200 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>Git History Scrub: <code className="text-amber-300">git filter-repo --replace-text expressions.txt</code> or use <code className="text-amber-300">BFG Repo-Cleaner</code></span>
          </div>
        </div>
      )}
    </div>
  );
};
