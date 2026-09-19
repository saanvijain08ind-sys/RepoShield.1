/**
 * AdvisoryMarkdown
 * Safe, GitHub-flavored markdown renderer for OSV vulnerability advisories
 * and AI-generated remediation bodies.
 *
 * Fixes raw-markdown rendering issues in vulnerability cards:
 * - `### Impact` / `### Patches` headers now render as real headers
 * - Links ([#698](...)) render as anchors with target="_blank" rel="noopener noreferrer"
 * - Fenced code blocks render monospace with horizontal scroll
 * - Headers word-wrap and break properly instead of overflowing the card
 */

import React, { useMemo } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

interface AdvisoryMarkdownProps {
  content: string;
  /** Compact mode for list rows; full mode for expanded cards / PR bodies. */
  variant?: 'compact' | 'full';
  className?: string;
}

const compactHeader = 'text-xs font-bold text-[#1a1a1c] dark:text-[#f0f6fc] font-syne tracking-tight';
const fullHeader = 'font-syne font-extrabold uppercase tracking-tight text-[#1a1a1c] dark:text-[#f0f6fc]';

export const AdvisoryMarkdown: React.FC<AdvisoryMarkdownProps> = ({
  content,
  variant = 'compact',
  className = '',
}) => {
  const remarkPlugins = useMemo(() => [remarkGfm], []);
  const isFull = variant === 'full';

  if (!content || !content.trim()) return null;

  return (
    <div
      className={`advisory-markdown break-words overflow-wrap-anywhere ${className}`}
      style={{ overflowWrap: 'anywhere' }}
    >
      <ReactMarkdown
        remarkPlugins={remarkPlugins}
        components={{
          h1: ({ children }) => (
            <h1 className={`${isFull ? 'text-lg' : 'text-sm'} ${fullHeader} break-words hyphens-auto mt-2 mb-1.5 first:mt-0`}>
              {children}
            </h1>
          ),
          h2: ({ children }) => (
            <h2 className={`${isFull ? 'text-base' : 'text-sm'} ${fullHeader} break-words hyphens-auto mt-2.5 mb-1.5 first:mt-0`}>
              {children}
            </h2>
          ),
          h3: ({ children }) => (
            <h3
              className={`${isFull ? 'text-sm' : 'text-xs'} ${fullHeader} border-b border-[#1a1a1c]/10 dark:border-[#f0f6fc]/10 pb-1 mb-1.5 break-words hyphens-auto first:mt-0`}
            >
              {children}
            </h3>
          ),
          h4: ({ children }) => (
            <h4 className={`text-xs ${compactHeader} break-words hyphens-auto mt-2 mb-1 first:mt-0`}>{children}</h4>
          ),
          p: ({ children }) => (
            <p className={`text-[#24292f] dark:text-[#d0d7de] leading-relaxed ${isFull ? 'text-sm' : 'text-xs'} mb-2 last:mb-0 break-words`}>
              {children}
            </p>
          ),
          a: ({ href, children }) => (
            <a
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              className="text-[#0969da] dark:text-[#58a6ff] hover:underline font-semibold"
            >
              {children}
            </a>
          ),
          ul: ({ children }) => (
            <ul className="list-disc pl-5 space-y-1 mb-2 last:mb-0 marker:text-[#2ea043]">{children}</ul>
          ),
          ol: ({ children }) => (
            <ol className="list-decimal pl-5 space-y-1 mb-2 last:mb-0 marker:text-[#2ea043]">{children}</ol>
          ),
          li: ({ children }) => (
            <li className={`text-[#24292f] dark:text-[#d0d7de] leading-relaxed ${isFull ? 'text-sm' : 'text-xs'} break-words`}>
              {children}
            </li>
          ),
          strong: ({ children }) => <strong className="font-bold text-[#1a1a1c] dark:text-[#f0f6fc]">{children}</strong>,
          blockquote: ({ children }) => (
            <blockquote className="border-l-4 border-[#d4a72c]/60 bg-[#fff8c5]/50 dark:bg-[#3d2e00]/20 pl-3 pr-2 py-1.5 my-2 text-xs text-[#57606a] dark:text-[#8b949e] break-words">
              {children}
            </blockquote>
          ),
          code: ({ className: cls, children, ...rest }) => {
            const isBlock = typeof cls === 'string' && cls.includes('language-');
            if (isBlock) {
              return (
                <code className="block font-mono-code text-xs text-emerald-300 whitespace-pre" {...rest}>
                  {children}
                </code>
              );
            }
            return (
              <code
                className="font-mono-code text-[11px] font-bold text-[#cf222e] dark:text-[#ff7b72] bg-[#f0f2f5] dark:bg-[#21262d] border border-[#1a1a1c]/10 dark:border-[#f0f6fc]/10 rounded px-1 py-0.5 break-all"
                {...rest}
              >
                {children}
              </code>
            );
          },
          pre: ({ children }) => (
            <pre className="bg-[#0d1117] border border-[#30363d] rounded p-3 my-2 overflow-x-auto max-w-full font-mono-code text-xs text-slate-200 leading-relaxed">
              {children}
            </pre>
          ),
          table: ({ children }) => (
            <div className="overflow-x-auto my-2 border border-[#1a1a1c]/15 dark:border-[#f0f6fc]/15">
              <table className="text-xs border-collapse w-full">{children}</table>
            </div>
          ),
          th: ({ children }) => (
            <th className="border border-[#1a1a1c]/15 dark:border-[#f0f6fc]/15 bg-[#f8f7f4] dark:bg-[#0f1117] px-2 py-1 text-left font-bold text-[#1a1a1c] dark:text-[#f0f6fc]">
              {children}
            </th>
          ),
          td: ({ children }) => (
            <td className="border border-[#1a1a1c]/15 dark:border-[#f0f6fc]/15 px-2 py-1 text-[#24292f] dark:text-[#d0d7de]">
              {children}
            </td>
          ),
          hr: () => <hr className="my-3 border-[#1a1a1c]/15 dark:border-[#f0f6fc]/15" />,
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
};
