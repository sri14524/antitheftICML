import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  MinusCircle,
  CheckCircle2,
  FileText,
  Info,
  Shield,
  Clock,
  ExternalLink,
  ChevronDown,
} from 'lucide-react';

export default function TrustScoreCard({ scanResult }) {
  if (!scanResult) return null;

  const score = scanResult.trustScore ?? 100;
  const verdict = (scanResult.verdict || 'safe').toLowerCase();
  const deductions = scanResult.deductions || [];
  const threatCategory = scanResult.threatCategory || 'General Threat Analysis';

  // Determine color theme
  let statusColor = {
    ring: '#10b981',
    text: 'text-emerald-400',
    border: 'border-emerald-500/30',
    bg: 'bg-emerald-500/10',
    verdictLabel: 'SAFE & VERIFIED',
    icon: ShieldCheck,
    tag: 'border-emerald-500/40 text-emerald-300 bg-emerald-950/60',
  };

  if (verdict === 'suspicious' || (score >= 50 && score < 80)) {
    statusColor = {
      ring: '#f59e0b',
      text: 'text-amber-400',
      border: 'border-amber-500/30',
      bg: 'bg-amber-500/10',
      verdictLabel: 'SUSPICIOUS VECTOR',
      icon: AlertTriangle,
      tag: 'border-amber-500/40 text-amber-300 bg-amber-950/60',
    };
  } else if (verdict === 'malicious' || score < 50) {
    statusColor = {
      ring: '#f43f5e',
      text: 'text-rose-400',
      border: 'border-rose-500/30',
      bg: 'bg-rose-500/10',
      verdictLabel: 'CRITICAL THREAT DETECTED',
      icon: ShieldAlert,
      tag: 'border-rose-500/40 text-rose-300 bg-rose-950/60',
    };
  }

  const StatusIcon = statusColor.icon;

  // SVG Gauge calculations
  const radius = 64;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="glass-panel rounded-3xl p-6 sm:p-8 border border-slate-800/80 mb-8 relative overflow-hidden">
      {/* Background ambient radial glow */}
      <div
        className="absolute -top-24 -left-24 w-72 h-72 rounded-full blur-3xl opacity-15 pointer-events-none"
        style={{ backgroundColor: statusColor.ring }}
      />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
        {/* Left Column: Radial Score HUD */}
        <div className="lg:col-span-5 flex flex-col items-center justify-center text-center p-4">
          <div className="relative w-44 h-44 flex items-center justify-center">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 160 160">
              {/* Background ring */}
              <circle
                cx="80"
                cy="80"
                r={radius}
                stroke="#1e293b"
                strokeWidth="12"
                fill="transparent"
              />
              {/* Animated Progress ring */}
              <circle
                cx="80"
                cy="80"
                r={radius}
                stroke={statusColor.ring}
                strokeWidth="12"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="transparent"
                style={{
                  transition: 'stroke-dashoffset 1s ease-in-out',
                  filter: `drop-shadow(0 0 8px ${statusColor.ring}80)`,
                }}
              />
            </svg>

            {/* Score in center */}
            <div className="absolute flex flex-col items-center justify-center">
              <span className="text-4xl sm:text-5xl font-black font-mono tracking-tight text-white">
                {score}
              </span>
              <span className="text-[11px] font-mono tracking-widest uppercase text-slate-400">
                TRUST INDEX
              </span>
            </div>
          </div>

          <div className="mt-4">
            <div
              className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border text-xs font-mono font-bold uppercase tracking-wider ${statusColor.tag}`}
            >
              <StatusIcon className="w-4 h-4" />
              <span>{statusColor.verdictLabel}</span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-2">{threatCategory}</p>
          </div>
        </div>

        {/* Right Column: Score Breakdown & Recommendation */}
        <div className="lg:col-span-7 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-mono uppercase tracking-wider text-slate-300">
                  Trust Score Audit Log & Deductions
                </h3>
              </div>
              <span className="text-xs font-mono text-slate-400">
                Base Baseline: 100 PTS
              </span>
            </div>

            {/* Deductions list */}
            {deductions.length === 0 ? (
              <div className="rounded-2xl p-5 bg-emerald-950/20 border border-emerald-500/25 flex items-start gap-4">
                <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
                  <CheckCircle2 className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="text-sm font-semibold text-emerald-300">
                    Zero Threat Deductions Incurred
                  </h4>
                  <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                    All global intelligence feeds returned clean telemetries. Domain age, SSL
                    encryption protocols, and reputation databases confirmed no anomalies.
                  </p>
                </div>
              </div>
            ) : (
              <div className="space-y-2.5 max-h-56 overflow-y-auto pr-1">
                {deductions.map((d, idx) => (
                  <div
                    key={idx}
                    className="rounded-xl p-3 bg-slate-900/80 border border-slate-800/90 hover:border-slate-700 transition-all flex items-start justify-between gap-3"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs font-semibold text-slate-200">{d.source}</span>
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded-full uppercase border ${
                            d.severity === 'Critical'
                              ? 'border-rose-500/40 text-rose-400 bg-rose-500/10'
                              : d.severity === 'High'
                              ? 'border-amber-500/40 text-amber-400 bg-amber-500/10'
                              : 'border-cyan-500/40 text-cyan-400 bg-cyan-500/10'
                          }`}
                        >
                          {d.severity}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 leading-snug">{d.reason}</p>
                      {d.impact && (
                        <p className="text-[11px] text-slate-400 mt-1 italic">
                          Impact: {d.impact}
                        </p>
                      )}
                    </div>

                    <div className="text-right shrink-0">
                      <span className="inline-block px-2.5 py-1 rounded-lg font-mono text-xs font-bold text-rose-400 bg-rose-500/10 border border-rose-500/25">
                        {d.penalty} PTS
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Actionable recommendation advisory */}
          <div className="mt-5 pt-4 border-t border-slate-800/80 flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 text-slate-400">
              <Shield className="w-4 h-4 text-cyan-400" />
              <span>
                {verdict === 'malicious'
                  ? 'Advisory: Block access across network endpoints. Never enter credentials.'
                  : verdict === 'suspicious'
                  ? 'Advisory: Exercise elevated caution. Verify target through out-of-band channels.'
                  : 'Advisory: Validated safe profile. Standard cyber hygiene practices apply.'}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
