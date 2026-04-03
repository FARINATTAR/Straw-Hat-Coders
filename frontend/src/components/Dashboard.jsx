import { useState, useEffect } from 'react';
import { Shield, Users, AlertTriangle, Activity, RefreshCw, TrendingUp, Ghost, Cpu, Siren, ChevronRight } from 'lucide-react';

const LEVEL_COLORS = {
  green: 'bg-emerald-500', yellow: 'bg-amber-400', orange: 'bg-orange-500', red: 'bg-red-500',
};
const LEVEL_DOT = {
  green: 'bg-emerald-400', yellow: 'bg-amber-400', orange: 'bg-orange-400', red: 'bg-red-400',
};
const LEVEL_TEXT = {
  green: 'text-emerald-600', yellow: 'text-amber-600', orange: 'text-orange-600', red: 'text-red-600',
};
const LEVEL_BG = {
  green: 'bg-emerald-50 border-emerald-200', yellow: 'bg-amber-50 border-amber-200',
  orange: 'bg-orange-50 border-orange-200', red: 'bg-red-50 border-red-200',
};

function AnimatedNumber({ value }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    const target = typeof value === 'number' ? value : parseFloat(value) || 0;
    const duration = 800;
    const start = performance.now();
    const initial = display;
    function tick(now) {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplay(Math.round(initial + (target - initial) * eased));
      if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }, [value]);
  return <>{display.toLocaleString()}</>;
}

export default function Dashboard({ data, users, onUserClick, onRefresh }) {
  const [coordinated, setCoordinated] = useState(null);

  useEffect(() => {
    fetch('/api/coordinated_attacks').then(r => r.json()).then(setCoordinated).catch(() => {});
  }, [data]);

  if (!data) return <div className="flex items-center justify-center h-full text-slate-400">Loading dashboard...</div>;

  const topRisky = users.filter(u => u.risk_score > 30).slice(0, 6);

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      {coordinated && coordinated.is_coordinated && (
        <div className="animate-fade-up bg-red-50 border border-red-200 rounded-2xl p-5 flex items-center gap-4">
          <div className="w-11 h-11 rounded-full bg-red-100 flex items-center justify-center shrink-0">
            <Siren className="w-5 h-5 text-red-600" />
          </div>
          <div className="flex-1">
            <p className="text-sm font-bold text-red-800">Coordinated Attack Detected</p>
            <p className="text-xs text-red-600 mt-0.5">
              {coordinated.correlated_users?.length || 0} users compromised simultaneously within 30-minute window.
            </p>
          </div>
          <span className="text-[10px] font-bold text-white bg-red-500 px-3 py-1.5 rounded-full uppercase tracking-wide">Critical</span>
        </div>
      )}

      <div className="flex items-end justify-between">
        <div>
          <h2 className="text-2xl font-bold text-slate-900 tracking-tight">Security Overview</h2>
          <p className="text-sm text-slate-400 mt-1">Real-time Zero Trust monitoring</p>
        </div>
        <button onClick={onRefresh} className="flex items-center gap-2 px-4 py-2 text-slate-500 rounded-xl hover:bg-slate-100 transition text-sm font-medium cursor-pointer">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      <div className="grid grid-cols-3 gap-5">
        <div className="animate-fade-up bg-white rounded-2xl border border-slate-200 p-6">
          <div className="flex items-center justify-between mb-4">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Users</span>
            <Users className="w-4 h-4 text-blue-500" />
          </div>
          <p className="text-4xl font-bold text-slate-900"><AnimatedNumber value={data.total_users} /></p>
          <p className="text-xs text-slate-400 mt-1">monitored in real-time</p>
        </div>

        <div className="animate-fade-up bg-white rounded-2xl border border-slate-200 p-6" style={{ animationDelay: '50ms' }}>
          <div className="flex items-center justify-between mb-4">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Alerts</span>
            <AlertTriangle className="w-4 h-4 text-red-500" />
          </div>
          <p className="text-4xl font-bold text-red-600"><AnimatedNumber value={data.total_alerts} /></p>
          <p className="text-xs text-slate-400 mt-1">{data.critical_alerts} critical</p>
        </div>

        <div className="animate-fade-up bg-white rounded-2xl border border-slate-200 p-6" style={{ animationDelay: '100ms' }}>
          <div className="flex items-center justify-between mb-4">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Avg Risk</span>
            <TrendingUp className="w-4 h-4 text-amber-500" />
          </div>
          <p className={`text-4xl font-bold ${data.average_risk_score > 60 ? 'text-red-600' : data.average_risk_score > 30 ? 'text-amber-600' : 'text-emerald-600'}`}>
            <AnimatedNumber value={data.average_risk_score} />
          </p>
          <p className="text-xs text-slate-400 mt-1">across all users</p>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-5">
        <div className="animate-fade-up bg-white rounded-2xl border border-slate-200 p-6" style={{ animationDelay: '150ms' }}>
          <div className="flex items-center justify-between mb-4">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Activity</span>
            <Activity className="w-4 h-4 text-violet-500" />
          </div>
          <p className="text-4xl font-bold text-slate-900"><AnimatedNumber value={data.total_activity_logs} /></p>
          <p className="text-xs text-slate-400 mt-1">{data.anomaly_rate}% anomaly rate</p>
        </div>

        <div className="animate-fade-up bg-white rounded-2xl border border-slate-200 p-6" style={{ animationDelay: '200ms' }}>
          <div className="flex items-center justify-between mb-4">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Ghost Accounts</span>
            <Ghost className="w-4 h-4 text-purple-500" />
          </div>
          <p className="text-4xl font-bold text-slate-900"><AnimatedNumber value={data.ghost_accounts ?? 0} /></p>
          <p className="text-xs text-slate-400 mt-1">dormant 14+ days</p>
        </div>

        <div className="animate-fade-up bg-white rounded-2xl border border-slate-200 p-6" style={{ animationDelay: '250ms' }}>
          <div className="flex items-center justify-between mb-4">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">AI Engines</span>
            <Cpu className="w-4 h-4 text-cyan-500" />
          </div>
          <p className="text-4xl font-bold text-cyan-600"><AnimatedNumber value={data.novel_detectors_active ?? 12} /></p>
          <p className="text-xs text-slate-400 mt-1">novel detectors active</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        <div className="lg:col-span-2 animate-fade-up bg-white rounded-2xl border border-slate-200 p-6" style={{ animationDelay: '100ms' }}>
          <h3 className="text-sm font-semibold text-slate-700 mb-5 flex items-center gap-2">
            <Shield className="w-4 h-4 text-blue-500" /> Risk Distribution
          </h3>
          <div className="space-y-4">
            {Object.entries(data.risk_distribution).map(([level, count]) => {
              const pct = data.total_users ? Math.round((count / data.total_users) * 100) : 0;
              return (
                <div key={level}>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs uppercase font-semibold text-slate-500">{level}</span>
                    <span className={`text-sm font-bold ${LEVEL_TEXT[level]}`}>{count}</span>
                  </div>
                  <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
                    <div className={`h-full ${LEVEL_COLORS[level]} rounded-full transition-all duration-700`} style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="lg:col-span-3 animate-fade-up bg-white rounded-2xl border border-slate-200 p-6" style={{ animationDelay: '150ms' }}>
          <h3 className="text-sm font-semibold text-slate-700 mb-5">Highest Risk Users</h3>
          {topRisky.length === 0 ? (
            <p className="text-sm text-slate-400 py-8 text-center">No elevated-risk users detected.</p>
          ) : (
            <div className="space-y-2">
              {topRisky.map(user => (
                <button
                  key={user.id}
                  onClick={() => onUserClick(user.id)}
                  className="w-full flex items-center gap-4 px-4 py-3 rounded-xl hover:bg-slate-50 transition-all cursor-pointer text-left group"
                >
                  <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${LEVEL_DOT[user.risk_level]}`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-slate-800">{user.full_name}</p>
                    <p className="text-xs text-slate-400">{user.department}</p>
                  </div>
                  {user.session_state !== 'active' && (
                    <span className={`text-[10px] px-2 py-0.5 rounded-full font-semibold uppercase border ${LEVEL_BG[user.risk_level]}`}>
                      {user.session_state}
                    </span>
                  )}
                  <span className={`text-lg font-bold tabular-nums ${LEVEL_TEXT[user.risk_level]}`}>{Math.round(user.risk_score)}</span>
                  <ChevronRight className="w-4 h-4 text-slate-300 group-hover:text-slate-500 transition" />
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
