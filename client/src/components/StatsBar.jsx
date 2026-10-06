import React from 'react';
import { ShieldCheck, ShieldAlert, Activity, CheckCircle2, TrendingUp, Info } from 'lucide-react';

export default function StatsBar({ stats }) {
  if (!stats) return null;

  const totalScans = stats.totalScans || 0;
  const safeCount = stats.safeCount || 0;
  const threatCount = (stats.suspiciousCount || 0) + (stats.maliciousCount || 0);
  const avgTrust = stats.avgTrustScore || 85;
  const agreementRate = stats.agreementRate || '94.2%';

  const safePercentage = totalScans > 0 ? Math.round((safeCount / totalScans) * 100) : 100;

  return (
    <div className="w-full mb-8">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 sm:gap-4">
        {/* Total Scans Card */}
        <div className="glass-panel rounded-2xl p-4 sm:p-5 border border-slate-800/80 hover:border-cyan-500/30 transition-all group">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Total Scans</span>
            <div className="w-7 h-7 rounded-lg bg-cyan-500/10 flex items-center justify-center text-cyan-400 group-hover:scale-110 transition-transform">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight font-mono">
              {totalScans}
            </span>
            <span className="text-xs text-cyan-400 font-mono">Live Intel</span>
          </div>
          <div className="w-full bg-slate-800/80 h-1.5 rounded-full mt-3 overflow-hidden">
            <div className="bg-gradient-to-r from-cyan-500 to-indigo-500 h-full rounded-full w-full"></div>
          </div>
        </div>

        {/* Clean / Safe Targets */}
        <div className="glass-panel rounded-2xl p-4 sm:p-5 border border-slate-800/80 hover:border-emerald-500/30 transition-all group">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Safe Targets</span>
            <div className="w-7 h-7 rounded-lg bg-emerald-500/10 flex items-center justify-center text-emerald-400 group-hover:scale-110 transition-transform">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl sm:text-3xl font-extrabold text-emerald-400 tracking-tight font-mono">
              {safeCount}
            </span>
            <span className="text-xs text-slate-400 font-mono">({safePercentage}%)</span>
          </div>
          <div className="w-full bg-slate-800/80 h-1.5 rounded-full mt-3 overflow-hidden">
            <div
              className="bg-emerald-400 h-full rounded-full transition-all duration-700"
              style={{ width: `${safePercentage}%` }}
            ></div>
          </div>
        </div>

        {/* Threats Intercepted */}
        <div className="glass-panel rounded-2xl p-4 sm:p-5 border border-slate-800/80 hover:border-rose-500/30 transition-all group">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Threats Flagged</span>
            <div className="w-7 h-7 rounded-lg bg-rose-500/10 flex items-center justify-center text-rose-400 group-hover:scale-110 transition-transform">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl sm:text-3xl font-extrabold text-rose-400 tracking-tight font-mono">
              {threatCount}
            </span>
            <span className="text-xs text-slate-400 font-mono">
              ({stats.maliciousCount || 0} crit / {stats.suspiciousCount || 0} susp)
            </span>
          </div>
          <div className="w-full bg-slate-800/80 h-1.5 rounded-full mt-3 overflow-hidden">
            <div
              className="bg-gradient-to-r from-amber-500 to-rose-500 h-full rounded-full transition-all duration-700"
              style={{ width: `${totalScans > 0 ? Math.min(100, (threatCount / totalScans) * 100) : 0}%` }}
            ></div>
          </div>
        </div>

        {/* Global Agreement / Trust Score */}
        <div className="glass-panel rounded-2xl p-4 sm:p-5 border border-slate-800/80 hover:border-cyan-500/30 transition-all group">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Consensus Rate</span>
            <div className="w-7 h-7 rounded-lg bg-cyan-500/10 flex items-center justify-center text-cyan-400 group-hover:scale-110 transition-transform">
              <TrendingUp className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl sm:text-3xl font-extrabold text-cyan-400 tracking-tight font-mono">
              {agreementRate}
            </span>
            <span className="text-xs text-slate-400 font-mono">Index {avgTrust}/100</span>
          </div>
          <div className="w-full bg-slate-800/80 h-1.5 rounded-full mt-3 overflow-hidden">
            <div
              className="bg-cyan-400 h-full rounded-full transition-all duration-700"
              style={{ width: agreementRate }}
            ></div>
          </div>
        </div>
      </div>
    </div>
  );
}
