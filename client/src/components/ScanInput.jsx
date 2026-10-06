import React, { useState, useRef } from 'react';
import {
  Search,
  Globe,
  QrCode,
  Phone,
  Mail,
  Sparkles,
  Upload,
  AlertCircle,
  CheckCircle,
  X,
  ArrowRight,
  ShieldAlert,
  Loader2,
  FileImage,
} from 'lucide-react';
import { decodeQrFromImageFile } from '../utils/qrDecoder';

const PRESET_VECTORS = [
  {
    name: 'Clean Infrastructure',
    type: 'url',
    value: 'https://github.com',
    badge: 'Safe (100)',
    badgeColor: 'border-emerald-500/30 text-emerald-400 bg-emerald-500/10',
    icon: Globe,
  },
  {
    name: 'PayPal Phishing Simulation',
    type: 'url',
    value: 'https://secure-login-paypal-verification.com/auth/login.php',
    badge: 'Phishing (0)',
    badgeColor: 'border-rose-500/30 text-rose-400 bg-rose-500/10',
    icon: Globe,
  },
  {
    name: 'Suspicious Crypto Airdrop',
    type: 'url',
    value: 'http://crypto-airdrop-claim-rewards-free.top',
    badge: 'Suspicious (45)',
    badgeColor: 'border-amber-500/30 text-amber-400 bg-amber-500/10',
    icon: Globe,
  },
  {
    name: 'Burner VoIP Telecom',
    type: 'phone',
    value: '+14155550199',
    badge: 'VoIP Risk (30)',
    badgeColor: 'border-rose-500/30 text-rose-400 bg-rose-500/10',
    icon: Phone,
  },
  {
    name: 'Disposable Burner Mail',
    type: 'email',
    value: 'support-alert@tempmail.com',
    badge: 'Disposable (25)',
    badgeColor: 'border-rose-500/30 text-rose-400 bg-rose-500/10',
    icon: Mail,
  },
];

export default function ScanInput({ onScan, isScanning }) {
  const [activeVector, setActiveVector] = useState('auto');
  const [inputValue, setInputValue] = useState('');
  const [selectedCountry, setSelectedCountry] = useState('US');
  const [qrState, setQrState] = useState({
    isDecoding: false,
    previewUrl: null,
    decodedText: null,
    error: null,
  });
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef(null);

  const handleSubmit = (e) => {
    e?.preventDefault();
    if (!inputValue.trim() || isScanning) return;
    onScan({
      input: inputValue.trim(),
      type: activeVector === 'auto' ? 'auto' : activeVector === 'qr' ? 'url' : activeVector,
      defaultCountry: selectedCountry,
    });
  };

  const handleApplyPreset = (preset) => {
    setActiveVector(preset.type);
    setInputValue(preset.value);
    onScan({
      input: preset.value,
      type: preset.type,
      defaultCountry: selectedCountry,
    });
  };

  const handleQrFile = async (file) => {
    if (!file) return;
    setQrState({ isDecoding: true, previewUrl: null, decodedText: null, error: null });

    try {
      const result = await decodeQrFromImageFile(file);
      if (result.success) {
        setQrState({
          isDecoding: false,
          previewUrl: result.previewUrl,
          decodedText: result.text,
          error: null,
        });
        setInputValue(result.text);
        // Auto trigger scan on decoded QR text
        onScan({
          input: result.text,
          type: 'auto',
          defaultCountry: selectedCountry,
        });
      } else {
        setQrState({
          isDecoding: false,
          previewUrl: result.previewUrl,
          decodedText: null,
          error: result.error,
        });
      }
    } catch (err) {
      setQrState({
        isDecoding: false,
        previewUrl: null,
        decodedText: null,
        error: err.message || 'Error processing QR image file.',
      });
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragOver(false);
    const files = e.dataTransfer.files;
    if (files && files[0]) {
      handleQrFile(files[0]);
    }
  };

  return (
    <div className="w-full glass-panel-glow rounded-3xl p-6 sm:p-8 mb-10 border border-cyan-500/30 relative overflow-hidden">
      {/* Decorative Cyber Accents */}
      <div className="absolute top-0 left-0 w-32 h-1 bg-gradient-to-r from-transparent via-cyan-400 to-transparent"></div>
      <div className="absolute top-0 right-0 w-32 h-1 bg-gradient-to-r from-transparent via-indigo-500 to-transparent"></div>

      {/* Vector Selector Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-6">
        <div className="flex flex-wrap items-center gap-1.5 p-1 bg-slate-900/90 rounded-2xl border border-slate-800">
          {[
            { id: 'auto', label: 'Auto-Detect', icon: Sparkles },
            { id: 'url', label: 'URL / Domain', icon: Globe },
            { id: 'qr', label: 'QR Lens', icon: QrCode },
            { id: 'phone', label: 'Phone Number', icon: Phone },
            { id: 'email', label: 'Email Address', icon: Mail },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeVector === tab.id;
            return (
              <button
                key={tab.id}
                id={`vector-tab-${tab.id}`}
                onClick={() => {
                  setActiveVector(tab.id);
                  if (tab.id === 'qr' && !inputValue) {
                    // Switch to QR mode
                  }
                }}
                className={`px-3.5 py-2 rounded-xl text-xs sm:text-sm font-medium transition-all flex items-center gap-2 ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/50 shadow-md shadow-cyan-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {activeVector === 'phone' && (
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-slate-400">DEFAULT REGION:</span>
            <select
              value={selectedCountry}
              onChange={(e) => setSelectedCountry(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1 text-cyan-300 font-mono focus:border-cyan-400 outline-none"
            >
              <option value="US">US (+1)</option>
              <option value="GB">UK (+44)</option>
              <option value="IN">IN (+91)</option>
              <option value="CA">CA (+1)</option>
              <option value="AU">AU (+61)</option>
              <option value="DE">DE (+49)</option>
              <option value="FR">FR (+33)</option>
            </select>
          </div>
        )}
      </div>

      {/* QR Code Upload / Drop Zone when QR tab is selected */}
      {activeVector === 'qr' && (
        <div className="mb-6">
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setIsDragOver(true);
            }}
            onDragLeave={() => setIsDragOver(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-2xl p-6 text-center cursor-pointer transition-all ${
              isDragOver
                ? 'border-cyan-400 bg-cyan-950/40 shadow-lg shadow-cyan-500/20'
                : 'border-slate-700/80 bg-slate-900/60 hover:border-cyan-500/50 hover:bg-slate-900/90'
            }`}
          >
            <input
              type="file"
              ref={fileInputRef}
              accept="image/*"
              className="hidden"
              onChange={(e) => {
                if (e.target.files?.[0]) handleQrFile(e.target.files[0]);
              }}
            />

            <div className="flex flex-col items-center justify-center gap-3">
              <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                {qrState.isDecoding ? (
                  <Loader2 className="w-6 h-6 animate-spin" />
                ) : (
                  <QrCode className="w-6 h-6" />
                )}
              </div>
              <div>
                <p className="text-sm font-semibold text-slate-200">
                  {qrState.isDecoding
                    ? 'Decoding QR Matrix...'
                    : 'Drop QR Code image here or click to browse'}
                </p>
                <p className="text-xs text-slate-400 mt-1">
                  Supports PNG, JPG, WebP, SVG screenshots & camera captures
                </p>
              </div>
            </div>
          </div>

          {qrState.previewUrl && (
            <div className="mt-4 p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center gap-4">
              <img
                src={qrState.previewUrl}
                alt="QR Preview"
                className="w-16 h-16 object-cover rounded-lg border border-slate-700"
              />
              <div className="flex-1 min-w-0">
                {qrState.decodedText ? (
                  <div>
                    <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-mono mb-1">
                      <CheckCircle className="w-3.5 h-3.5" /> Decoded Target URL:
                    </div>
                    <p className="text-sm font-mono text-cyan-300 truncate">{qrState.decodedText}</p>
                  </div>
                ) : qrState.error ? (
                  <div>
                    <div className="flex items-center gap-1.5 text-xs text-rose-400 font-mono mb-1">
                      <AlertCircle className="w-3.5 h-3.5" /> Decode Alert:
                    </div>
                    <p className="text-xs text-slate-300">{qrState.error}</p>
                  </div>
                ) : null}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Main Target Input Bar */}
      <form onSubmit={handleSubmit} className="relative mb-6">
        <div className="relative flex items-center">
          <div className="absolute left-4 text-cyan-400 pointer-events-none">
            {activeVector === 'phone' ? (
              <Phone className="w-5 h-5" />
            ) : activeVector === 'email' ? (
              <Mail className="w-5 h-5" />
            ) : activeVector === 'qr' ? (
              <QrCode className="w-5 h-5" />
            ) : (
              <Search className="w-5 h-5" />
            )}
          </div>

          <input
            id="target-input-field"
            type="text"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            placeholder={
              activeVector === 'phone'
                ? 'Enter phone number (e.g. +14155550199 or 4155550199)...'
                : activeVector === 'email'
                ? 'Enter email address (e.g. alert@suspicious-bank.com)...'
                : activeVector === 'qr'
                ? 'Extracted QR URL or target...'
                : 'Enter URL, Web Domain, Phone Number, or Email target...'
            }
            className="w-full pl-12 pr-40 py-4 bg-slate-950/80 border border-cyan-500/30 rounded-2xl text-slate-100 placeholder-slate-500 font-mono text-sm sm:text-base focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/20 outline-none transition-all shadow-inner"
          />

          {inputValue && (
            <button
              type="button"
              onClick={() => setInputValue('')}
              className="absolute right-36 text-slate-400 hover:text-slate-200 p-1"
            >
              <X className="w-4 h-4" />
            </button>
          )}

          <button
            id="scan-submit-btn"
            type="submit"
            disabled={!inputValue.trim() || isScanning}
            className="absolute right-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-semibold text-xs sm:text-sm tracking-wide shadow-lg shadow-cyan-500/25 flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed transition-all active:scale-95"
          >
            {isScanning ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-white" />
                <span className="font-mono">ANALYZING...</span>
              </>
            ) : (
              <>
                <ShieldAlert className="w-4 h-4" />
                <span className="font-mono">EVALUATE</span>
                <ArrowRight className="w-3.5 h-3.5 hidden sm:inline" />
              </>
            )}
          </button>
        </div>
      </form>

      {/* Preset Vectors / Quick Intelligence Demos */}
      <div>
        <div className="flex items-center gap-2 mb-3">
          <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
            Quick Intel Demos & Simulations
          </span>
        </div>
        <div className="flex flex-wrap gap-2">
          {PRESET_VECTORS.map((preset, idx) => {
            const Icon = preset.icon;
            return (
              <button
                key={idx}
                id={`preset-btn-${idx}`}
                onClick={() => handleApplyPreset(preset)}
                className="px-3 py-1.5 rounded-xl bg-slate-900/80 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 text-xs font-mono transition-all flex items-center gap-2 text-slate-300 group"
              >
                <Icon className="w-3.5 h-3.5 text-cyan-400 group-hover:scale-110 transition-transform" />
                <span>{preset.name}</span>
                <span className={`text-[10px] px-1.5 py-0.5 rounded border ${preset.badgeColor}`}>
                  {preset.badge}
                </span>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
