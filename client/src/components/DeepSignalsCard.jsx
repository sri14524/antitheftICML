import React, { useState } from 'react';
import {
  Shield,
  Lock,
  Unlock,
  Globe,
  Server,
  ArrowRight,
  Clock,
  MapPin,
  Building,
  PhoneCall,
  MailCheck,
  AlertCircle,
  CheckCircle2,
  ExternalLink,
  Layers,
  Copy,
  Check,
} from 'lucide-react';

export default function DeepSignalsCard({ scanResult }) {
  if (!scanResult) return null;

  const [copied, setCopied] = useState(false);
  const inputType = scanResult.inputType || 'url';
  const signals = scanResult.signals || {};
  const metadata = scanResult.metadata || {};

  const handleCopyTarget = () => {
    navigator.clipboard?.writeText(scanResult.input || '');
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="glass-panel rounded-3xl p-6 sm:p-8 border border-slate-800/80 mb-8">
      {/* Target Title & Quick Actions */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6 pb-6 border-b border-slate-800">
        <div>
          <span className="text-[11px] font-mono uppercase tracking-wider text-cyan-400">
            Forensic Target Profile
          </span>
          <h3 className="text-lg sm:text-xl font-mono font-bold text-white break-all flex items-center gap-2 mt-1">
            <span>{scanResult.input}</span>
            <button
              onClick={handleCopyTarget}
              title="Copy target"
              className="p-1 rounded-lg text-slate-400 hover:text-cyan-400 hover:bg-slate-800 transition"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>
          </h3>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="px-3 py-1 rounded-full bg-slate-900 border border-slate-700 text-slate-300">
            Type: {inputType.toUpperCase()}
          </span>
          <span className="px-3 py-1 rounded-full bg-slate-900 border border-slate-700 text-slate-400">
            Scan ID: {scanResult.scanId || 'tl_live'}
          </span>
        </div>
      </div>

      {/* URL Deep Forensics */}
      {inputType === 'url' && (
        <div className="space-y-6">
          {/* Grid of Key Network Badges */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* SSL / TLS Status */}
            <div className="rounded-2xl p-4 bg-slate-900/60 border border-slate-800">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
                <span>SSL / TLS SECURITY</span>
                {metadata.sslValid ? (
                  <Lock className="w-4 h-4 text-emerald-400" />
                ) : (
                  <Unlock className="w-4 h-4 text-rose-400" />
                )}
              </div>
              <div className="text-sm font-bold text-white">
                {metadata.sslValid ? 'Valid TLS Encryption' : 'Unencrypted / Expired'}
              </div>
              <div className="text-xs text-slate-400 font-mono mt-1">
                {metadata.sslDaysRemaining ? `${metadata.sslDaysRemaining} days remaining` : 'No valid cert'}
              </div>
              <div className="text-[11px] text-cyan-400 font-mono truncate mt-0.5">
                {metadata.sslIssuer || 'Self-signed / None'}
              </div>
            </div>

            {/* WHOIS Domain Age */}
            <div className="rounded-2xl p-4 bg-slate-900/60 border border-slate-800">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
                <span>DOMAIN LIFESPAN</span>
                <Clock className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="text-sm font-bold text-white">
                {metadata.domainAgeDays != null ? `${metadata.domainAgeDays} Days Old` : 'Age Unknown'}
              </div>
              <div className="text-xs text-slate-400 font-mono mt-1">
                {metadata.domainAgeDays < 14 ? '⚠️ Fresh Domain (<14d)' : 'Established Identity'}
              </div>
              <div className="text-[11px] text-slate-400 font-mono truncate mt-0.5">
                {metadata.registrar || 'ICANN Registry'}
              </div>
            </div>

            {/* Origin & Geography */}
            <div className="rounded-2xl p-4 bg-slate-900/60 border border-slate-800">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
                <span>HOSTING REGION</span>
                <MapPin className="w-4 h-4 text-indigo-400" />
              </div>
              <div className="text-sm font-bold text-white truncate">
                {metadata.country || 'Global Anycast'}
              </div>
              <div className="text-xs text-slate-400 font-mono mt-1 truncate">
                IP: {metadata.ip || 'DNS Dynamic'}
              </div>
              <div className="text-[11px] text-cyan-400 font-mono truncate mt-0.5">
                {metadata.asn || 'Cloud Edge Provider'}
              </div>
            </div>

            {/* Protocol & Scheme */}
            <div className="rounded-2xl p-4 bg-slate-900/60 border border-slate-800">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
                <span>SCHEME PROTOCOL</span>
                <Globe className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="text-sm font-bold text-white">
                {metadata.protocol ? metadata.protocol.toUpperCase().replace(':', '') : 'HTTPS'}
              </div>
              <div className="text-xs text-slate-400 font-mono mt-1 truncate">
                Host: {metadata.hostname || 'Normalized'}
              </div>
              <div className="text-[11px] text-emerald-400 font-mono truncate mt-0.5">
                Standard Web Port 443
              </div>
            </div>
          </div>

          {/* Redirect Chain / Hopkins Route Inspector */}
          {metadata.redirectChain && metadata.redirectChain.length > 0 && (
            <div className="rounded-2xl p-5 bg-slate-900/40 border border-slate-800">
              <div className="flex items-center gap-2 mb-3">
                <Layers className="w-4 h-4 text-cyan-400" />
                <h4 className="text-xs font-mono uppercase tracking-wider text-slate-300">
                  HTTP Redirect Hopkins & Cloaking Trace ({metadata.redirectChain.length} Hop{metadata.redirectChain.length > 1 ? 's' : ''})
                </h4>
              </div>

              <div className="space-y-2">
                {metadata.redirectChain.map((hop, idx) => (
                  <div
                    key={idx}
                    className="flex items-center gap-3 text-xs font-mono p-2.5 rounded-xl bg-slate-900/90 border border-slate-800"
                  >
                    <span className="w-6 h-6 rounded-lg bg-cyan-500/10 text-cyan-400 flex items-center justify-center font-bold text-[11px] shrink-0">
                      #{idx + 1}
                    </span>
                    <span className="text-slate-400 font-bold shrink-0">
                      [{hop.status || 200}]
                    </span>
                    <span className="text-slate-200 truncate flex-1">{hop.url}</span>
                    {idx === metadata.redirectChain.length - 1 && (
                      <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 shrink-0">
                        Final Land
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Phone Number Deep Forensics */}
      {inputType === 'phone' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="rounded-2xl p-5 bg-slate-900/60 border border-slate-800 space-y-3 font-mono text-xs">
            <div className="flex justify-between border-b border-slate-800 pb-2">
              <span className="text-slate-400">International E.164:</span>
              <span className="text-white font-bold">{signals.international || scanResult.input}</span>
            </div>
            <div className="flex justify-between border-b border-slate-800 pb-2">
              <span className="text-slate-400">Country Code:</span>
              <span className="text-cyan-400 font-bold">{signals.country || 'US'} (+{signals.countryCallingCode || '1'})</span>
            </div>
            <div className="flex justify-between border-b border-slate-800 pb-2">
              <span className="text-slate-400">Carrier Provider:</span>
              <span className="text-slate-200">{signals.carrier || 'Standard Telecom'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Line Type:</span>
              <span className="text-cyan-300 font-bold">{signals.lineType || 'Mobile / Landline'}</span>
            </div>
          </div>

          <div className="rounded-2xl p-5 bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-2 mb-2 text-xs font-mono">
                {signals.isVoip ? (
                  <span className="px-2.5 py-1 rounded-full bg-rose-500/10 border border-rose-500/30 text-rose-400 font-bold">
                    ⚠️ VOIP / VIRTUAL LINE DETECTED
                  </span>
                ) : (
                  <span className="px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-bold">
                    ✓ TELECOM REGISTERED LINE
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-300 leading-relaxed mt-2">
                {signals.isVoip
                  ? 'This number is provisioned through a Virtual Voice-over-IP or burner provider. Cybercriminals frequently use VoIP services for untraceable robocalls and SMS phishing (smishing) campaigns.'
                  : 'This number matches a registered mobile or wireline operator carrier with physical SIM registration records.'}
              </p>
            </div>
            <div className="text-[11px] font-mono text-slate-400 mt-4 pt-3 border-t border-slate-800">
              Telecom Trust Verification Score: {scanResult.trustScore}/100
            </div>
          </div>
        </div>
      )}

      {/* Email Deep Forensics */}
      {inputType === 'email' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="rounded-2xl p-5 bg-slate-900/60 border border-slate-800 space-y-3 font-mono text-xs">
            <div className="flex justify-between border-b border-slate-800 pb-2">
              <span className="text-slate-400">Target Email:</span>
              <span className="text-white font-bold truncate max-w-[200px]">{signals.email || scanResult.input}</span>
            </div>
            <div className="flex justify-between border-b border-slate-800 pb-2">
              <span className="text-slate-400">Domain Name:</span>
              <span className="text-cyan-400 font-bold">{signals.domain}</span>
            </div>
            <div className="flex justify-between border-b border-slate-800 pb-2">
              <span className="text-slate-400">DNS MX Mail Exchangers:</span>
              <span className="text-slate-200">{signals.mxCount || 0} Records</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Burner / Temp Service:</span>
              <span className={signals.isDisposable ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                {signals.isDisposable ? 'Flagged Burner Mail' : 'Clean Corporate / Public'}
              </span>
            </div>
          </div>

          <div className="rounded-2xl p-5 bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-2 mb-2 text-xs font-mono">
                {signals.hasValidMx ? (
                  <span className="px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-bold">
                    ✓ VALID DNS MX EXCHANGERS
                  </span>
                ) : (
                  <span className="px-2.5 py-1 rounded-full bg-rose-500/10 border border-rose-500/30 text-rose-400 font-bold">
                    ⚠️ MISSING MX RECORDS / SPOOF RISK
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-300 leading-relaxed mt-2">
                {signals.isDisposable
                  ? 'Domain is listed on global temporary email blacklists used for disposable registrations and throwaway accounts.'
                  : signals.hasValidMx
                  ? 'Domain has legitimate DNS Mail Exchange routing records properly configured to receive email traffic.'
                  : 'Domain lacks valid mail servers. Messages sent claiming to originate from this domain are at high risk of being forged or spoofed.'}
              </p>
            </div>
            <div className="text-[11px] font-mono text-slate-400 mt-4 pt-3 border-t border-slate-800">
              Email Deliverability & Authenticity Index: {scanResult.trustScore}/100
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
