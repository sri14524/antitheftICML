import React, { useState, useEffect } from 'react';
import { apiFetch } from '../utils/api';
import {
  Database,
  Search,
  Filter,
  Trash2,
  Download,
  RefreshCw,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Globe,
  Phone,
  Mail,
  Clock,
  ArrowUpRight,
  Check,
  Copy,
} from 'lucide-react';

export default function ScanHistory({ onSelectScan, onHistoryUpdated }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [isClearing, setIsClearing] = useState(false);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (searchTerm) params.append('search', searchTerm);
      if (verdictFilter !== 'all') params.append('verdict', verdictFilter);
      if (typeFilter !== 'all') params.append('type', typeFilter);
      params.append('limit', '60');

      const data = await apiFetch(`/api/scans?${params.toString()}`);
      if (data?.success) {
        setScans(data.scans || []);
      }
    } catch (err) {
      console.error('Failed to load history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [searchTerm, verdictFilter, typeFilter]);

  const handleClearHistory = async () => {
    if (!window.confirm('Are you sure you want to delete all historical threat scan records? This action cannot be undone.')) {
      return;
    }
    setIsClearing(true);
    try {
      await apiFetch('/api/scans', { method: 'DELETE' });
      await fetchHistory();
      if (onHistoryUpdated) onHistoryUpdated();
    } catch (err) {
      console.error('Error clearing history:', err);
    } finally {
      setIsClearing(false);
    }
  };

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(scans, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `threatlens-archive-${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const getVerdictBadge = (verdict, score) => {
    const v = (verdict || 'safe').toLowerCase();
    if (v === 'safe') {
      return (
        <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
          SAFE ({score})
        </span>
      );
    }
    if (v === 'suspicious') {
      return (
        <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
          SUSP ({score})
        </span>
      );
    }
    return (
      <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
        MALICIOUS ({score})
      </span>
    );
  };

  const getTypeIcon = (type) => {
    if (type === 'phone') return <Phone className="w-3.5 h-3.5 text-cyan-400" />;
    if (type === 'email') return <Mail className="w-3.5 h-3.5 text-cyan-400" />;
    return <Globe className="w-3.5 h-3.5 text-cyan-400" />;
  };

  return (
    <div className="w-full glass-panel rounded-3xl p-6 sm:p-8 border border-slate-800/80 mb-10">
      {/* Title & Top Action Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6 pb-6 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white tracking-wide">
              Threat Intelligence Archive & Telemetry Logs
            </h2>
            <p className="text-xs text-slate-400 font-mono">
              Persistent forensic database of evaluated targets and cross-feed detections
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchHistory}
            disabled={loading}
            className="p-2 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/40 text-slate-300 hover:text-cyan-400 transition"
            title="Refresh logs"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>

          <button
            onClick={handleExportJson}
            disabled={scans.length === 0}
            className="px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/40 text-slate-300 hover:text-cyan-400 text-xs font-mono transition flex items-center gap-1.5 disabled:opacity-40"
          >
            <Download className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Export JSON</span>
          </button>

          <button
            onClick={handleClearHistory}
            disabled={scans.length === 0 || isClearing}
            className="px-3 py-2 rounded-xl bg-rose-950/30 border border-rose-500/30 hover:bg-rose-900/40 text-rose-300 text-xs font-mono transition flex items-center gap-1.5 disabled:opacity-40"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Clear Archive</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-6">
        {/* Search Input */}
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search targets by URL, domain, phone, or email..."
            className="w-full pl-10 pr-4 py-2 bg-slate-900/80 border border-slate-800 rounded-xl text-xs sm:text-sm font-mono text-slate-100 placeholder-slate-500 focus:border-cyan-400 outline-none"
          />
        </div>

        {/* Verdict Filters */}
        <div className="flex items-center gap-1 bg-slate-900/80 p-1 rounded-xl border border-slate-800 text-xs font-mono">
          {['all', 'safe', 'suspicious', 'malicious'].map((v) => (
            <button
              key={v}
              onClick={() => setVerdictFilter(v)}
              className={`px-2.5 py-1 rounded-lg capitalize transition ${
                verdictFilter === v
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {v}
            </button>
          ))}
        </div>

        {/* Type Filters */}
        <div className="flex items-center gap-1 bg-slate-900/80 p-1 rounded-xl border border-slate-800 text-xs font-mono">
          {['all', 'url', 'phone', 'email'].map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={`px-2.5 py-1 rounded-lg uppercase transition ${
                typeFilter === t
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {/* Scans List */}
      {loading ? (
        <div className="py-16 text-center text-slate-400 font-mono text-xs flex flex-col items-center gap-2">
          <RefreshCw className="w-5 h-5 animate-spin text-cyan-400" />
          <span>Retrieving archived threat telemetry...</span>
        </div>
      ) : scans.length === 0 ? (
        <div className="py-16 text-center text-slate-400 font-mono text-xs">
          <Database className="w-8 h-8 text-slate-600 mx-auto mb-2 opacity-50" />
          <p>No historical records matching the active filters.</p>
          <p className="text-[11px] text-slate-500 mt-1">Run scans from the Target Analyzer to populate archive.</p>
        </div>
      ) : (
        <div className="space-y-2.5 max-h-[460px] overflow-y-auto pr-1">
          {scans.map((scan) => (
            <div
              key={scan.id}
              className="p-3.5 rounded-2xl bg-slate-900/80 border border-slate-800/90 hover:border-cyan-500/40 transition-all flex flex-wrap items-center justify-between gap-3 group"
            >
              <div className="flex items-center gap-3 min-w-0 flex-1">
                <div className="w-8 h-8 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-center shrink-0">
                  {getTypeIcon(scan.input_type)}
                </div>

                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs sm:text-sm font-mono font-bold text-slate-200 truncate group-hover:text-cyan-300 transition-colors">
                      {scan.input_value}
                    </span>
                    {getVerdictBadge(scan.verdict, scan.trust_score)}
                  </div>

                  <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400 mt-1">
                    <span className="text-slate-400">{scan.threat_category || 'Evaluated Vector'}</span>
                    <span>•</span>
                    <span className="flex items-center gap-1 text-slate-400">
                      <Clock className="w-3 h-3 text-slate-400" />
                      {new Date(scan.created_at).toLocaleDateString()} {new Date(scan.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                </div>
              </div>

              {/* Action: Reload Scan Dossier */}
              <button
                id={`inspect-scan-${scan.id}`}
                onClick={() => {
                  onSelectScan({
                    scanId: scan.id,
                    input: scan.input_value,
                    inputType: scan.input_type,
                    trustScore: scan.trust_score,
                    verdict: scan.verdict,
                    threatCategory: scan.threat_category,
                    signals: scan.signals,
                    externalVerdicts: scan.external_verdicts,
                    metadata: scan.metadata,
                    timestamp: scan.created_at,
                    deductions: scan.signals?.deductions || [],
                  });
                }}
                className="px-3 py-1.5 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-xs font-mono transition flex items-center gap-1.5 shrink-0"
              >
                <span>Inspect Dossier</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
