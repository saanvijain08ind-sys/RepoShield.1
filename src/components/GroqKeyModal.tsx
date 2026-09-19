import React, { useEffect, useState } from 'react';
import { X, KeyRound, Eye, EyeOff, CheckCircle2, AlertCircle, ExternalLink } from 'lucide-react';
import {
  getStoredGroqKey,
  setStoredGroqKey,
  maskGroqKey,
} from '../services/groqKeyStore.ts';

interface GroqKeyModalProps {
  isOpen: boolean;
  onClose: () => void;
  /** True when the server reports a GROQ_API_KEY is configured. */
  serverKeyConfigured: boolean;
}

export const GroqKeyModal: React.FC<GroqKeyModalProps> = ({
  isOpen,
  onClose,
  serverKeyConfigured,
}) => {
  const [key, setKey] = useState('');
  const [reveal, setReveal] = useState(false);
  const [savedFlash, setSavedFlash] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setKey(getStoredGroqKey());
      setSavedFlash(false);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleSave = () => {
    setStoredGroqKey(key);
    setSavedFlash(true);
    setTimeout(() => onClose(), 650);
  };

  const handleRemove = () => {
    setStoredGroqKey('');
    setKey('');
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 dark:bg-black/70 backdrop-blur-xs">
      <div className="bg-white dark:bg-[#161b22] rounded-md shadow-2xl max-w-md w-full overflow-hidden border border-[#d0d7de] dark:border-[#30363d] transition-colors">
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#d0d7de] dark:border-[#30363d] bg-[#f6f8fa] dark:bg-[#161b22]">
          <div className="flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-[#2ea043]" />
            <div>
              <h2 className="text-sm font-semibold text-[#1f2328] dark:text-[#f0f6fc]">Groq API Key</h2>
              <p className="text-xs text-[#656d76] dark:text-[#8b949e]">
                {serverKeyConfigured
                  ? 'Server key configured — a personal key overrides it'
                  : 'Server key not set — add your own key to enable AI features'}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-[#656d76] dark:text-[#8b949e] hover:text-[#1f2328] dark:hover:text-[#f0f6fc] p-1 rounded-md transition-colors"
            aria-label="Close Groq key modal"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-4">
          <div
            className={`p-3 border rounded-md flex items-start gap-2 text-xs ${
              serverKeyConfigured
                ? 'bg-[#dafbe1] dark:bg-[#0d4429]/40 border-[#4ac26b]/40 text-[#1a7f37] dark:text-[#3fb950]'
                : 'bg-[#fff8c5] dark:bg-[#3d2e00]/40 border-[#d4a72c]/40 text-[#9a6700] dark:text-[#d4a72c]'
            }`}
          >
            {serverKeyConfigured ? (
              <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
            ) : (
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            )}
            <span>
              {serverKeyConfigured
                ? 'The server environment provides GROQ_API_KEY. AI features are enabled for everyone.'
                : 'AI remediation and outreach need a Groq key. Yours is stored only in this browser (localStorage) and sent per-request — never stored server-side.'}
            </span>
          </div>

          <div>
            <label
              htmlFor="groq-key-input"
              className="block text-xs font-semibold text-[#1f2328] dark:text-[#f0f6fc] mb-1.5"
            >
              Personal Groq API Key
            </label>
            <div className="relative">
              <input
                id="groq-key-input"
                type={reveal ? 'text' : 'password'}
                value={key}
                onChange={(e) => setKey(e.target.value)}
                placeholder="gsk_..."
                autoComplete="off"
                spellCheck={false}
                className="w-full px-3 py-2 pr-10 text-sm font-mono bg-white dark:bg-[#0d1117] border border-[#d0d7de] dark:border-[#30363d] rounded-md text-[#1f2328] dark:text-[#f0f6fc] placeholder-[#8b949e] focus:outline-none focus:ring-2 focus:ring-[#2ea043]/60"
              />
              <button
                type="button"
                onClick={() => setReveal((r) => !r)}
                className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-[#656d76] dark:text-[#8b949e] hover:text-[#1f2328] dark:hover:text-[#f0f6fc]"
                aria-label={reveal ? 'Hide key' : 'Reveal key'}
              >
                {reveal ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {getStoredGroqKey() && (
            <p className="text-xs font-mono text-[#656d76] dark:text-[#8b949e]">
              Currently saved: <span className="font-bold">{maskGroqKey(getStoredGroqKey())}</span>
            </p>
          )}

          <a
            href="https://console.groq.com/keys"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs font-semibold text-[#0969da] dark:text-[#58a6ff] hover:underline"
          >
            Get a free Groq API key
            <ExternalLink className="w-3 h-3" />
          </a>

          <div className="flex items-center justify-between pt-1">
            <button
              onClick={handleRemove}
              disabled={!getStoredGroqKey()}
              className="text-xs font-semibold text-[#cf222e] dark:text-[#ff7b72] hover:underline disabled:opacity-40 disabled:no-underline"
            >
              Remove saved key
            </button>
            <div className="flex items-center gap-2">
              <button
                onClick={onClose}
                className="px-3.5 py-2 text-xs font-semibold text-[#1f2328] dark:text-[#f0f6fc] bg-[#f6f8fa] dark:bg-[#21262d] hover:bg-[#eaeef2] dark:hover:bg-[#30363d] border border-[#d0d7de] dark:border-[#30363d] rounded-md transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                className="px-3.5 py-2 text-xs font-bold text-white bg-[#2ea043] hover:bg-[#2c9740] border border-[#1a1a1c] rounded-md transition-colors"
              >
                {savedFlash ? 'Saved ✓' : 'Save Key'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
