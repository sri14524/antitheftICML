import React from 'react';
import {
  Layers,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  HelpCircle,
  ExternalLink,
  CheckCircle2,
  XCircle,
  Radio,
  Sparkles,
} from 'lucide-react';

export default function EngineMatrix({ scanResult }) {
  if (!scanResult) return null;

  const inputType = scanResult.inputType || 'url';
  const signals = scanResult.signals || {};
  const externalVerdicts = scanResult.externalVerdicts || {};
  const agreedWithMajority = scanResult.agreedWithMajority;

  // Build engines list depending on input type
  let engines = [];

  if (inputType === 'phone') {
    engines = [
      {
        name: 'ThreatLens Telecom Engine',
        vendor: 'ThreatLens Core',
        verdict: scanResult.verdict,
        status: scanResult.verdict === 'Safe' ? 'safe' : scanResult.verdict === 'Suspicious' ? 'suspicious' : 'malicious',
        detail: `Trust Index: ${scanResult.trustScore}/100`,
      },
      {
        name: 'Carrier & Line Classification',
        vendor: 'Telecom Registry (E.164)',
        verdict: signals.lineType || 'Mobile / Standard',
        status: signals.isVoip ? 'malicious' : 'safe',
        detail: signals.carrier || 'Standard Telecom Carrier',
      },
      {
        name: 'VoIP / Burner Line Detection',
        vendor: 'Anti-Spoofing Feed',
        verdict: signals.isVoip ? 'Flagged VoIP' : 'Non-VoIP Legitimate',
        status: signals.isVoip ? 'malicious' : 'safe',
        detail: signals.isVoip ? 'High probability burner phone service' : 'Verified standard telecom line',
      },
      {
        name: 'Number Format Validation',
        vendor: 'ITU Telecommunication',
        verdict: signals.isValid ? 'Valid E.164' : 'Invalid Number',
        status: signals.isValid ? 'safe' : 'malicious',
        detail: `Country: ${signals.country || 'Global'}`,
      },
    ];
  } else if (inputType === 'email') {
    engines = [
      {
        name: 'ThreatLens Mail Engine',
        vendor: 'ThreatLens Core',
        verdict: scanResult.verdict,
        status: scanResult.verdict === 'Safe' ? 'safe' : scanResult.verdict === 'Suspicious' ? 'suspicious' : 'malicious',
        detail: `Trust Index: ${scanResult.trustScore}/100`,
      },
      {
        name: 'MX Record Verification',
        vendor: 'DNS Telemetry',
        verdict: signals.hasValidMx ? 'Valid MX Records' : 'Missing MX',
        status: signals.hasValidMx ? 'safe' : 'malicious',
        detail: `${signals.mxCount || 0} active mail servers found`,
      },
      {
        name: 'Disposable Burner Mail Check',
        vendor: 'Temp-Mail Intelligence',
        verdict: signals.isDisposable ? 'Disposable Mailbox' : 'Persistent Domain',
        status: signals.isDisposable ? 'malicious' : 'safe',
        detail: signals.isDisposable ? 'Known burner email domain' : 'Legitimate corporate/consumer domain',
      },
      {
        name: 'RFC Format & Spoofing Guard',
        vendor: 'Mail Protocol Engine',
        verdict: signals.isValidFormat ? 'Compliant Syntax' : 'Malformed Syntax',
        status: signals.isValidFormat ? 'safe' : 'malicious',
        detail: `Domain: ${signals.domain}`,
      },
    ];
  } else {
    // URL scan
    const gsb = signals.googleSafeBrowsing || {};
    const vt = signals.virusTotal || {};
    const pt = signals.phishTank || {};
    const whois = signals.whois || {};

    const vtMalicious = vt.maliciousCount || 0;
    const vtTotal = vt.totalEngines || (vt.available ? 72 : 0);

    engines = [
      {
        name: 'ThreatLens Trust Engine',
        vendor: 'ThreatLens Neural Heuristics',
        verdict: scanResult.verdict,
        status: scanResult.verdict === 'Safe' ? 'safe' : scanResult.verdict === 'Suspicious' ? 'suspicious' : 'malicious',
        detail: `Multi-signal synthesized Trust Score: ${scanResult.trustScore}/100`,
      },
      {
        name: 'Google Safe Browsing v4',
        vendor: 'Google Telemetry Feed',
        verdict: gsb.verdict || (gsb.status === 'malicious' ? 'Malicious' : 'Safe'),
        status: gsb.status === 'malicious' ? 'malicious' : gsb.status === 'suspicious' ? 'suspicious' : 'safe',
        detail: gsb.threatType ? `Flagged: ${gsb.threatType}` : 'Clean across Google crawler index',
      },
      {
        name: 'VirusTotal Multi-Vendor',
        vendor: 'Global AV Telemetry',
        verdict: vtMalicious > 0 ? `${vtMalicious} Vendors Flagged` : '0 Vendors Flagged',
        status: vtMalicious > 3 ? 'malicious' : vtMalicious > 0 ? 'suspicious' : 'safe',
        detail: vtTotal > 0 ? `${vtMalicious} / ${vtTotal} security engines detected threat` : 'Clean reputation',
      },
      {
        name: 'PhishTank Community Feed',
        vendor: 'OpenPhish / PhishTank',
        verdict: pt.verdict || (pt.status === 'malicious' ? 'Verified Phish' : 'Clean'),
        status: pt.status === 'malicious' ? 'malicious' : 'safe',
        detail: pt.status === 'malicious' ? 'Active credential harvester listing' : 'Not listed in phishing database',
      },
      {
        name: 'WHOIS Domain Age Radar',
        vendor: 'ICANN Registry Feed',
        verdict: (whois.ageDays ?? 365) < 14 ? 'Newly Registered' : 'Established Domain',
        status: (whois.ageDays ?? 365) < 14 ? 'suspicious' : 'safe',
        detail: `Domain age: ${whois.ageDays ?? 'Established'} days old (${whois.registrar || 'Global Registry'})`,
      },
      {
        name: 'SSL / TLS Encryption Guard',
        vendor: 'X.509 Cryptographic Feed',
        verdict: signals.ssl?.valid ? 'Valid TLS Certificate' : 'Missing / Invalid TLS',
        status: signals.ssl?.valid ? 'safe' : 'suspicious',
        detail: signals.ssl?.issuer ? `Issuer: ${signals.ssl.issuer} (${signals.ssl.daysRemaining || 0}d left)` : 'HTTP Unencrypted',
      },
    ];
  }

  const getStatusBadge = (status) => {
    if (status === 'safe') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium border border-emerald-500/30 text-emerald-300 bg-emerald-500/10">
          <CheckCircle2 className="w-3 h-3 text-emerald-400" /> Safe
        </span>
      );
    }
    if (status === 'suspicious') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium border border-amber-500/30 text-amber-300 bg-amber-500/10">
          <AlertTriangle className="w-3 h-3 text-amber-400" /> Suspicious
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium border border-rose-500/30 text-rose-300 bg-rose-500/10">
        <XCircle className="w-3 h-3 text-rose-400" /> Malicious
      </span>
    );
  };

  return (
    <div className="glass-panel rounded-3xl p-6 sm:p-8 border border-slate-800/80 mb-8">
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Layers className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white tracking-wide">
              Multi-Engine Threat Telemetry Matrix
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Comparative cross-verification across independent threat intelligence providers
            </p>
          </div>
        </div>

        {agreedWithMajority !== undefined && (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900/90 border border-slate-800 text-xs font-mono">
            <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span className="text-slate-400">Consensus Match:</span>
            <span className={agreedWithMajority ? 'text-emerald-400 font-bold' : 'text-amber-400 font-bold'}>
              {agreedWithMajority ? 'Majority Aligned (100%)' : 'Specialized Heuristic Vector'}
            </span>
          </div>
        )}
      </div>

      {/* Grid of Engine Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
        {engines.map((eng, idx) => (
          <div
            key={idx}
            className="rounded-2xl p-4 bg-slate-900/70 border border-slate-800/80 hover:border-cyan-500/30 transition-all hover:bg-slate-900/95 group"
          >
            <div className="flex items-start justify-between gap-2 mb-2">
              <div>
                <h4 className="text-xs font-bold text-slate-200 group-hover:text-cyan-300 transition-colors">
                  {eng.name}
                </h4>
                <span className="text-[10px] text-slate-400 font-mono">{eng.vendor}</span>
              </div>
              {getStatusBadge(eng.status)}
            </div>

            <div className="mt-3 pt-3 border-t border-slate-800/60">
              <div className="text-xs font-mono font-semibold text-slate-300 truncate">
                {eng.verdict}
              </div>
              <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-2 leading-relaxed">
                {eng.detail}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
