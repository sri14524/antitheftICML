import React from 'react';
import { ShieldAlert, ShieldCheck, Activity, Terminal, Database, Sparkles, RefreshCw } from 'lucide-react';

export default function Header({
  backendStatus,
  agreementStats,
  activeTab,
  setActiveTab,
  historyCount = 0,
}) {
  return (
    <header className="border-b border-cyan-500/20 bg-cyber-900/80 backdrop-blur-xl sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand / Logo */}
        <div className="flex items-center gap-3">
          <div className="relative group cursor-pointer" onClick={() => setActiveTab('scanner')}>
            <div className="absolute -inset-0.5 bg-gradient-to-r from-cyan-500 to-indigo-500 rounded-xl blur opacity-60 group-hover:opacity-100 transition duration-300"></div>
            <div className="relative w-10 h-10 rounded-xl bg-slate-950 flex items-center justify-center border border-cyan-500/40">
              <ShieldAlert className="w-5 h-5 text-cyan-400 group-hover:rotate-12 transition-transform duration-300" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold text-xl tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-200 to-indigo-300 font-sans">
                THREAT<span className="text-cyan-400">LENS</span>
              </span>
              <span className="text-[10px] uppercase font-mono tracking-widest px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-500/30 text-cyan-400">
                v1.0 INTEL
              </span>
            </div>
            <p className="text-[11px] text-slate-400 hidden sm:block tracking-wide">
              Multi-Vector Phishing & Cyber Threat Intelligence Engine
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="hidden md:flex items-center gap-1 bg-slate-900/90 border border-slate-800 rounded-xl p-1">
          <button
            id="nav-scanner-btn"
            onClick={() => setActiveTab('scanner')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 ${
              activeTab === 'scanner'
                ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            Threat Scanner
          </button>

          <button
            id="nav-history-btn"
            onClick={() => setActiveTab('history')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 ${
              activeTab === 'history'
                ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Database className="w-3.5 h-3.5" />
            Scan Archive
            {historyCount > 0 && (
              <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                {historyCount}
              </span>
            )}
          </button>
        </nav>

        {/* Status Indicators */}
        <div className="flex items-center gap-3">
          {/* Agreement Rate Pill */}
          {agreementStats && (
            <div
              className="hidden lg:flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-full bg-slate-900/90 border border-cyan-500/25 text-slate-300"
              title="Consensus rate between ThreatLens and global threat feeds"
            >
              <Sparkles className="w-3 h-3 text-cyan-400" />
              <span className="text-slate-400">FEED CONSENSUS:</span>
              <span className="text-cyan-400 font-bold">{agreementStats.agreementRate}</span>
            </div>
          )}

          {/* Engine Status Pill */}
          <div className="flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-full bg-slate-900/90 border border-slate-700/80">
            <span
              className={`w-2 h-2 rounded-full ${
                backendStatus === 'online'
                  ? 'bg-emerald-400 shadow-sm shadow-emerald-400 animate-pulse'
                  : 'bg-amber-400'
              }`}
            />
            <span className="text-slate-400 hidden sm:inline">ENGINE:</span>
            <span
              className={
                backendStatus === 'online' ? 'text-emerald-400 font-bold' : 'text-amber-400 font-bold'
              }
            >
              {backendStatus.toUpperCase()}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}
