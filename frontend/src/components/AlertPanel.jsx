import { useState, useMemo } from 'react';
import { ShieldAlert, RefreshCw, AlertTriangle, Info, Zap, Network, ChevronDown, ChevronUp } from 'lucide-react';

const SEV_CONFIG = {
  critical: { color: 'text-red-600', bg: 'bg-red-50', border: 'border-red-200', dot: 'bg-red-500', icon: Zap },
  high:     { color: 'text-orange-600', bg: 'bg-orange-50', border: 'border-orange-200', dot: 'bg-orange-400', icon: AlertTriangle },
  medium:   { color: 'text-amber-600', bg: 'bg-amber-50', border: 'border-amber-200', dot: 'bg-amber-400', icon: Info },
  low:      { color: 'text-emerald-600', bg: 'bg-emerald-50', border: 'border-emerald-200', dot: 'bg-emerald-400', icon: Info },
};

const TYPE_LABELS = {
  contagion: { label: 'Risk Contagion', icon: Network, style: 'bg-violet-50 text-violet-700 border-violet-200' },
  anomaly: { label: 'Anomaly', icon: AlertTriangle, style: 'bg-red-50 text-red-700 border-red-200' },
  honeypot: { label: 'Honeypot', icon: Zap, style: 'bg-rose-50 text-rose-700 border-rose-200' },
};

function groupAlertsByUser(alerts) {
  const map = {};
  for (const a of alerts) {
    const key = `${a.username}_${a.type}`;
    if (!map[key]) {
      map[key] = { ...a, count: 1, items: [a] };
    } else {
      map[key].count++;
      map[key].items.push(a);
    }
  }
  return Object.values(map).sort((a, b) => {
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return (sevOrder[a.severity] || 9) - (sevOrder[b.severity] || 9);
  });
}

export default function AlertPanel({ alerts, onRefresh, onUserClick }) {
  const [severityFilter, setSeverityFilter] = useState('all');
  const [expandedGroup, setExpandedGroup] = useState(null);

  const filtered = useMemo(() => {
    return alerts.filter(a => severityFilter === 'all' || a.severity === severityFilter);
  }, [alerts, severityFilter]);

  const grouped = useMemo(() => groupAlertsByUser(filtered), [filtered]);

  const counts = useMemo(() => ({
    critical: alerts.filter(a => a.severity === 'critical').length,
    high: alerts.filter(a => a.severity === 'high').length,
    medium: alerts.filter(a => a.severity === 'medium').length,
    low: alerts.filter(a => a.severity === 'low').length,
  }), [alerts]);

  return (
    <div className="space-y-5 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-900">Security Alerts</h2>
          <p className="text-xs text-slate-400 mt-0.5">{alerts.length} total alerts</p>
        </div>
        <button onClick={onRefresh} className="flex items-center gap-2 px-3.5 py-2 bg-white text-slate-600 rounded-xl hover:bg-slate-50 transition text-xs cursor-pointer border border-slate-200 font-medium">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {/* Severity Filter Tabs */}
      <div className="flex gap-1.5 bg-slate-100 p-1 rounded-xl w-fit">
        {[
          { key: 'all', label: 'All' },
          { key: 'critical', label: 'Critical' },
          { key: 'high', label: 'High' },
          { key: 'medium', label: 'Medium' },
          { key: 'low', label: 'Low' },
        ].map(tab => {
          const active = severityFilter === tab.key;
          const count = tab.key === 'all' ? alerts.length : counts[tab.key];
          return (
            <button key={tab.key} onClick={() => setSeverityFilter(tab.key)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer flex items-center gap-1.5 ${
                active ? 'bg-white text-slate-800 shadow-sm' : 'text-slate-500 hover:text-slate-700'
              }`}>
              {tab.key !== 'all' && <span className={`w-1.5 h-1.5 rounded-full ${SEV_CONFIG[tab.key]?.dot}`} />}
              {tab.label}
              {count > 0 && <span className={`text-[10px] ${active ? 'text-slate-500' : 'text-slate-400'}`}>{count}</span>}
            </button>
          );
        })}
      </div>

      {/* Grouped Alert List */}
      <div className="space-y-2">
        {grouped.length === 0 && (
          <div className="text-center py-16 text-slate-400">
            <ShieldAlert className="w-10 h-10 mx-auto mb-3 opacity-20" />
            <p className="text-sm">No alerts matching filter</p>
          </div>
        )}

        {grouped.map((group, i) => {
          const sev = SEV_CONFIG[group.severity] || SEV_CONFIG.medium;
          const SevIcon = sev.icon;
          const typeInfo = TYPE_LABELS[group.type] || { label: group.type, icon: Info, style: 'bg-slate-50 text-slate-600 border-slate-200' };
          const TypeIcon = typeInfo.icon;
          const isExpanded = expandedGroup === `${group.username}_${group.type}`;
          const hasMultiple = group.count > 1;

          return (
            <div key={`${group.username}_${group.type}_${i}`}
              className="bg-white rounded-xl border border-slate-200 overflow-hidden animate-fade-up"
              style={{ animationDelay: `${i * 20}ms` }}
            >
              {/* Main Row */}
              <div className="flex items-center gap-3 px-4 py-3.5">
                {/* Severity Icon */}
                <div className={`w-8 h-8 rounded-lg ${sev.bg} flex items-center justify-center shrink-0`}>
                  <SevIcon className={`w-4 h-4 ${sev.color}`} />
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <button onClick={() => onUserClick(group.user_id)}
                      className="text-sm font-semibold text-blue-600 hover:text-blue-800 cursor-pointer transition">
                      @{group.username}
                    </button>
                    <span className={`text-[10px] px-2 py-0.5 rounded-md font-semibold border ${typeInfo.style} flex items-center gap-1`}>
                      <TypeIcon className="w-3 h-3" /> {typeInfo.label}
                    </span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold uppercase ${sev.color}`}>
                      {group.severity}
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed line-clamp-1">{group.message}</p>
                </div>

                {/* Right side */}
                <div className="flex items-center gap-3 shrink-0">
                  <span className="text-[11px] text-slate-400">{new Date(group.timestamp).toLocaleTimeString()}</span>
                  {hasMultiple && (
                    <button onClick={() => setExpandedGroup(isExpanded ? null : `${group.username}_${group.type}`)}
                      className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-600 cursor-pointer transition">
                      +{group.count - 1} more
                      {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                    </button>
                  )}
                </div>
              </div>

              {/* Expanded Sub-alerts */}
              {isExpanded && hasMultiple && (
                <div className="border-t border-slate-100 bg-slate-50/50 px-4 py-2 space-y-1.5">
                  {group.items.slice(1).map((sub, j) => (
                    <div key={sub.id || j} className="flex items-center gap-3 py-1.5 text-xs">
                      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${sev.dot}`} />
                      <span className="flex-1 text-slate-500 line-clamp-1">{sub.message}</span>
                      <span className="text-slate-400 shrink-0">{new Date(sub.timestamp).toLocaleTimeString()}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
