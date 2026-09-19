/**
 * SentinelOSS - Main Application
 * Early-Warning Security Transition Tool for Open-Source Maintainers
 */

import React, { useState } from 'react';
import {
  Shield,
  Github,
  Sparkles,
  Terminal,
  Activity,
  Heart,
  TrendingUp,
} from 'lucide-react';
import { Header } from './components/Header.tsx';
import { SentinelFlow } from './components/SentinelFlow.tsx';
import { TestSuiteModal } from './components/TestSuiteModal.tsx';
import { ProjectRegistrationModal } from './components/ProjectRegistrationModal.tsx';
import { GroqKeyModal } from './components/GroqKeyModal.tsx';
import { hasStoredGroqKey } from './services/groqKeyStore.ts';

export default function App() {
  const [isTestOpen, setIsTestOpen] = useState(false);
  const [isRegisterOpen, setIsRegisterOpen] = useState(false);
  const [isGroqKeyOpen, setIsGroqKeyOpen] = useState(false);
  const [hasServerGroqKey, setHasServerGroqKey] = useState(false);
  const [hasLocalGroqKey, setHasLocalGroqKey] = useState(hasStoredGroqKey());
  const [currentRepo, setCurrentRepo] = useState('superprompt-cli');

  // Probe the server for its Groq/GitHub credential configuration on mount
  React.useEffect(() => {
    fetch('/api/sentinel/groq-status')
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (data && typeof data.groqConfigured === 'boolean') {
          setHasServerGroqKey(data.groqConfigured);
        }
      })
      .catch(() => {
        // Offline / API unavailable: leave as false, modal still usable
      });
  }, []);

  return (
    <div className="min-h-screen bg-[var(--bg)] text-[var(--ink)] flex flex-col font-sans antialiased transition-colors">
      {/* GitHub-Themed Header */}
      <Header
        currentRepo={currentRepo}
        onOpenRegister={() => setIsRegisterOpen(true)}
        onOpenTestSuite={() => setIsTestOpen(true)}
        onOpenGroqKey={() => setIsGroqKeyOpen(true)}
        groqKeyState={hasServerGroqKey ? 'server' : hasLocalGroqKey ? 'local' : 'missing'}
      />

      <div className="flex-1 w-full">
        {/* Primary Interactive Sentinel Flow */}
        <SentinelFlow
          currentRepo={currentRepo}
          onRepoChange={setCurrentRepo}
          onOpenTestSuite={() => setIsTestOpen(true)}
        />
      </div>

      {/* Automated In-App Test Suite Modal */}
      <TestSuiteModal isOpen={isTestOpen} onClose={() => setIsTestOpen(false)} />

      {/* Register Target Modal */}
      <ProjectRegistrationModal
        isOpen={isRegisterOpen}
        onClose={() => setIsRegisterOpen(false)}
        onRegistered={(newProj) => {
          setCurrentRepo(newProj.name);
        }}
      />

      {/* Groq API Key Modal (user-supplied key persisted to localStorage) */}
      <GroqKeyModal
        isOpen={isGroqKeyOpen}
        onClose={() => {
          setHasLocalGroqKey(hasStoredGroqKey());
          setIsGroqKeyOpen(false);
        }}
        serverKeyConfigured={hasServerGroqKey}
      />

      {/* Clean Variation 2 Footer */}
      <footer className="border-t-2 border-[#1a1a1c] dark:border-[#f0f6fc] bg-[var(--bg)] py-6 text-xs font-mono-code text-[#1a1a1c]/70 dark:text-[#f0f6fc]/70 transition-colors">
        <div className="w-full px-6 sm:px-10 flex items-center gap-2.5">
          <Shield className="w-4 h-4 text-[#2ea043]" />
          <span>
            <strong className="font-bold text-[var(--ink)]">RepoShield</strong> v1.0.4 — Early-warning security transition & remediation for open-source maintainers.
          </span>
        </div>
      </footer>
    </div>
  );
}
