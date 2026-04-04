import { useState } from 'react';
import { Play, Zap, UserX, TrendingUp, Loader2, CheckCircle2, Users, Database, Ghost, KeyRound, Crosshair, Fingerprint, Network, Flame, BarChart3, Rocket, ChevronDown, ChevronUp } from 'lucide-react';
import { api } from '../utils/api';

const SCENARIOS = [
  {
    id: 'data_exfiltrator', title: 'Rogue Employee (Data Theft)',
    description: 'Detects an employee downloading massive amounts of sensitive files in the middle of the night.',
    icon: Zap, iconColor: 'text-rose-400', cardBg: 'bg-rose-50/60', borderColor: 'border-rose-200',
    user: 'bob.johnson',
    details: ['Off-hours login at 2:30 AM', '47 sensitive file downloads in 15 min', 'Abnormal data volume (500MB+)', 'Session auto-terminated'],
  },
  {
    id: 'compromised_account', title: 'Stolen Credentials (VPN)',
    description: 'Detects a hacker logging in from an unfamiliar country and trying to access restricted folders.',
    icon: UserX, iconColor: 'text-purple-400', cardBg: 'bg-purple-50/60', borderColor: 'border-purple-200',
    user: 'eve.jones',
    details: ['Login from "Unknown VPN, Russia"', 'Unknown device detected', 'HONEYPOT trap triggered', 'Immediate account lockout'],
  },
  {
    id: 'slow_insider', title: 'The "Slow" Insider Threat',
    description: 'Detects an employee slowly hoarding access to files over several days to avoid triggering alarms.',
    icon: TrendingUp, iconColor: 'text-amber-400', cardBg: 'bg-amber-50/60', borderColor: 'border-amber-200',
    user: 'henry.davis',
    details: ['Gradual scope expansion over 7 days', 'Cross-department access increases daily', 'Peer group deviation detected', 'Behavioral DNA shift identified'],
  },
  {
    id: 'credential_sharing', title: 'Impossible Travel (Shared Password)',
    description: 'Detects the same account being used from two completely different countries at the exact same time.',
    icon: Users, iconColor: 'text-sky-400', cardBg: 'bg-sky-50/60', borderColor: 'border-sky-200',
    user: 'charlie.williams', badge: 'NOVEL',
    details: ['IMPOSSIBLE TRAVEL: Mumbai to London in 5 min', 'Concurrent sessions from different IPs', 'Behavioral velocity shift (3x+ change)'],
  },
  {
    id: 'data_staging', title: 'Data Hoarding (Pre-Theft)',
    description: 'Detects an attacker quietly gathering files into a single location before attempting to steal them.',
    icon: Database, iconColor: 'text-emerald-400', cardBg: 'bg-emerald-50/60', borderColor: 'border-emerald-200',
    user: 'diana.brown', badge: 'NOVEL',
    details: ['Resource diversity explosion (25+ resources)', 'Cross-department data collection', 'Aggregation velocity spike'],
  },
  {
    id: 'ghost_account', title: 'Dead Account Hijack',
    description: 'Detects an old, inactive employee account suddenly waking up and instantly accessing sensitive files.',
    icon: Ghost, iconColor: 'text-violet-400', cardBg: 'bg-violet-50/60', borderColor: 'border-violet-200',
    user: 'ivy.rodriguez', badge: 'NOVEL',
    details: ['Account dormant 20+ days', 'Sudden reactivation from anonymous proxy', 'Immediate sensitive file access'],
  },
  {
    id: 'kill_chain', title: 'Full Attack Lifecycle',
    description: 'Tracks a sophisticated attacker moving step-by-step from initial scanning all the way to stealing data.',
    icon: Crosshair, iconColor: 'text-red-400', cardBg: 'bg-red-50/60', borderColor: 'border-red-200',
    user: 'nathan.wilson', badge: 'RESEARCH',
    details: ['Full Lockheed Martin Kill Chain mapped', 'Recon to Lateral to Collection to Exfil', 'Real-time phase progression tracking'],
  },
  {
    id: 'coordinated_attack', title: 'Coordinated Attack (Multi-User)',
    description: 'Detects multiple employee accounts being hacked at the exact same time by an organized group.',
    icon: Network, iconColor: 'text-rose-400', cardBg: 'bg-rose-50/60', borderColor: 'border-rose-200',
    user: 'karen + leo + mona', badge: 'RESEARCH',
    details: ['3 accounts compromised in 15-min window', 'Cross-user temporal correlation', 'APT group pattern detection'],
  },
  {
    id: 'micro_burst', title: '"Hit and Run" Data Theft',
    description: 'Detects an attacker stealing data in tiny, hidden 10-second bursts to sneak past strict security rules.',
    icon: Flame, iconColor: 'text-orange-400', cardBg: 'bg-orange-50/60', borderColor: 'border-orange-200',
    user: 'paul.thomas', badge: 'RESEARCH',
    details: ['3 hidden bursts of 20MB in <60 seconds', 'Normal browsing between bursts', 'Burst-hide-burst evasion pattern'],
  },
];

export default function SimulationPanel({ onRefresh }) {
  const [running, setRunning] = useState(null);
  const [results, setResults] = useState({});
  const [runAllActive, setRunAllActive] = useState(false);
  const [runAllProgress, setRunAllProgress] = useState(0);
  const [modalData, setModalData] = useState(null);

  const runScenario = async (scenarioId) => {
    setRunning(scenarioId);
    setResults(prev => ({ ...prev, [scenarioId]: null }));
    try {
      const result = await api.simulate(scenarioId);
      setResults(prev => ({ ...prev, [scenarioId]: result }));
      onRefresh();
    } catch (e) {
      setResults(prev => ({ ...prev, [scenarioId]: { error: e.message } }));
    }
    setRunning(null);
  };

  const runAllScenarios = async () => {
    setRunAllActive(true);
    setRunAllProgress(0);
    for (let i = 0; i < SCENARIOS.length; i++) {
      setRunAllProgress(i + 1);
      await runScenario(SCENARIOS[i].id);
      await new Promise(r => setTimeout(r, 300));
    }
    setRunAllActive(false);
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-900 flex items-center gap-2">
            <Play className="w-5 h-5 text-blue-500" /> Live Threat Simulation
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Trigger real-time attack scenarios and watch the system detect, score, and respond
          </p>
        </div>
        <button
          onClick={runAllScenarios}
          disabled={runAllActive}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-xl font-medium text-sm transition-all cursor-pointer shadow-sm ${
            runAllActive
              ? 'bg-slate-100 text-slate-400 cursor-not-allowed'
              : 'bg-blue-600 text-white hover:bg-blue-700'
          }`}
        >
          {runAllActive ? (
            <><Loader2 className="w-4 h-4 animate-spin" /> Running {runAllProgress}/{SCENARIOS.length}...</>
          ) : (
            <><Rocket className="w-4 h-4" /> Run All 9 Scenarios</>
          )}
        </button>
      </div>

      {runAllActive && (
        <div className="w-full bg-slate-100 rounded-full h-1.5 overflow-hidden">
          <div
            className="h-full bg-blue-500 rounded-full transition-all duration-500"
            style={{ width: `${(runAllProgress / SCENARIOS.length) * 100}%` }}
          />
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {SCENARIOS.map((scenario, idx) => {
          const Icon = scenario.icon;
          const result = results[scenario.id];
          const isRunning = running === scenario.id;

          return (
            <div key={scenario.id}
              className={`animate-fade-up rounded-2xl border ${scenario.borderColor} ${scenario.cardBg} p-5 flex flex-col`}
              style={{ animationDelay: `${idx * 30}ms` }}
            >
              <div className="flex items-center gap-3 mb-3">
                <div className={`w-10 h-10 rounded-xl bg-white/80 flex items-center justify-center shrink-0 border ${scenario.borderColor}`}>
                  <Icon className={`w-5 h-5 ${scenario.iconColor}`} />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-bold text-slate-800 truncate">{scenario.title}</h3>
                    {scenario.badge && (
                      <span className={`text-[9px] px-1.5 py-0.5 rounded-md font-bold shrink-0 border ${
                        scenario.badge === 'RESEARCH' ? 'bg-violet-50 text-violet-600 border-violet-200' : 'bg-blue-50 text-blue-600 border-blue-200'
                      }`}>{scenario.badge}</span>
                    )}
                  </div>
                </div>
              </div>

              <p className="text-xs text-slate-500 leading-relaxed flex-1">{scenario.description}</p>

              <div className="mt-3 space-y-1">
                {scenario.details.map((d, i) => (
                  <div key={i} className="flex items-start gap-2 text-[11px] text-slate-400">
                    <span className="w-1 h-1 rounded-full bg-slate-300 mt-1.5 shrink-0" /> {d}
                  </div>
                ))}
              </div>

              <button
                onClick={() => runScenario(scenario.id)}
                disabled={isRunning}
                className={`mt-4 w-full py-2.5 rounded-xl font-medium text-xs transition-all cursor-pointer flex items-center justify-center gap-2 border ${
                  isRunning
                    ? 'bg-white text-slate-400 border-slate-200 cursor-not-allowed'
                    : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50 hover:border-slate-300'
                }`}
              >
                {isRunning ? (
                  <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Running...</>
                ) : (
                  <><Play className="w-3.5 h-3.5" /> Launch Scenario</>
                )}
              </button>

              {result && !result.error && (
                <div className="mt-3 p-3 rounded-xl bg-white border border-slate-200 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
                      <span className="text-[10px] text-emerald-600 font-semibold">Detected</span>
                    </div>
                    <span className={`text-lg font-bold ${
                      result.risk_level === 'red' ? 'text-red-500' :
                      result.risk_level === 'orange' ? 'text-orange-500' :
                      result.risk_level === 'yellow' ? 'text-amber-500' : 'text-emerald-500'
                    }`}>{Math.round(result.risk_score)}/100</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5 pt-2 border-t border-slate-100">
                    {result.markov_score > 0 && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded-md bg-slate-100 text-slate-600 font-medium">Markov {(result.markov_score * 100).toFixed(0)}%</span>
                    )}
                    {result.stealth_score > 0 && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded-md bg-slate-100 text-slate-600 font-medium">Stealth {(result.stealth_score * 100).toFixed(0)}%</span>
                    )}
                    {result.contagion_spread > 0 && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded-md bg-slate-100 text-slate-600 font-medium">Contagion {result.contagion_spread}</span>
                    )}
                    {result.credential_sharing_score > 0 && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded-md bg-slate-100 text-slate-600 font-medium">Cred Share {(result.credential_sharing_score * 100).toFixed(0)}%</span>
                    )}
                    {result.staging_score > 0 && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded-md bg-slate-100 text-slate-600 font-medium">Staging: {result.staging_phase}</span>
                    )}
                    {result.ghost_score > 0 && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded-md bg-slate-100 text-slate-600 font-medium">Ghost {result.dormancy_days}d</span>
                    )}
                    {result.privilege_creep_score > 0 && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded-md bg-slate-100 text-slate-600 font-medium">Creep {result.privilege_sprawl_pct?.toFixed(0)}%</span>
                    )}
                    {result.kill_chain_phase && result.kill_chain_phase !== 'none' && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded-md bg-slate-100 text-slate-600 font-medium">Kill Chain: {result.kill_chain_phase}</span>
                    )}
                    {result.biometric_score > 0 && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded-md bg-slate-100 text-slate-600 font-medium">Biometric {(result.biometric_score * 100).toFixed(0)}%</span>
                    )}
                    {result.coordination_detected && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded-md bg-rose-50 text-rose-600 font-bold border border-rose-200">COORDINATED: {result.users_compromised} users</span>
                    )}
                    {result.burst_score > 0 && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded-md bg-slate-100 text-slate-600 font-medium">Bursts {result.num_bursts}x ({result.max_burst_mb}MB)</span>
                    )}
                    {result.entropy_score > 0 && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded-md bg-slate-100 text-slate-600 font-medium">Entropy {result.entropy_ratio?.toFixed(1)}x</span>
                    )}
                  </div>
                  {result.narrative && (
                    <div className="border-t border-slate-100 pt-2 mt-1">
                      <p className="text-[10px] text-slate-500 leading-relaxed line-clamp-2">{result.narrative}</p>
                      <button onClick={() => setModalData({ title: scenario.title, result })}
                        className="flex items-center gap-1 text-[10px] text-blue-500 font-medium mt-1 cursor-pointer hover:text-blue-700">
                        <ChevronDown className="w-3 h-3" /> Full narrative
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {modalData && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-6" onClick={() => setModalData(null)}>
          <div className="absolute inset-0 bg-black/30 backdrop-blur-sm" />
          <div className="relative bg-white rounded-2xl border border-slate-200 shadow-2xl max-w-lg w-full max-h-[80vh] overflow-y-auto p-6"
            onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-bold text-slate-800">{modalData.title}</h3>
              <div className={`text-lg font-bold ${
                modalData.result.risk_level === 'red' ? 'text-red-500' :
                modalData.result.risk_level === 'orange' ? 'text-orange-500' :
                modalData.result.risk_level === 'yellow' ? 'text-amber-500' : 'text-emerald-500'
              }`}>{Math.round(modalData.result.risk_score)}/100</div>
            </div>
            <div className="text-sm text-slate-600 leading-relaxed whitespace-pre-wrap">
              {modalData.result.narrative}
            </div>
            <button onClick={() => setModalData(null)}
              className="mt-5 w-full py-2.5 rounded-xl bg-slate-100 text-slate-600 text-sm font-medium hover:bg-slate-200 transition cursor-pointer">
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
