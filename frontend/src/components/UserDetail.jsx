import { useState, useEffect } from 'react';
import { ArrowLeft, MapPin, Clock, AlertCircle, ShieldCheck, ShieldX, Network, GitBranch, Eye, Users, Database, Ghost, KeyRound, Crosshair, Fingerprint, Flame, BarChart3, Download, ChevronDown, ChevronUp } from 'lucide-react';
import { api } from '../utils/api';
import RiskGauge from './RiskGauge';

const ACTION_COLORS = { login: 'text-blue-600', logout: 'text-slate-400', file_access: 'text-violet-600', download: 'text-orange-600', api_call: 'text-emerald-600', failed_login: 'text-red-600' };

const NOVEL_ICONS = {
    'Credential': { icon: Users, color: 'text-cyan-700 bg-cyan-50 border-cyan-200' },
    'staging': { icon: Database, color: 'text-emerald-700 bg-emerald-50 border-emerald-200' },
    'Ghost': { icon: Ghost, color: 'text-violet-700 bg-violet-50 border-violet-200' },
    'Privilege': { icon: KeyRound, color: 'text-rose-700 bg-rose-50 border-rose-200' },
    'Markov': { icon: GitBranch, color: 'text-purple-700 bg-purple-50 border-purple-200' },
    'evasion': { icon: Eye, color: 'text-amber-700 bg-amber-50 border-amber-200' },
    'Stealth': { icon: Eye, color: 'text-amber-700 bg-amber-50 border-amber-200' },
    'Kill Chain': { icon: Crosshair, color: 'text-red-700 bg-red-50 border-red-200' },
    'biometric': { icon: Fingerprint, color: 'text-indigo-700 bg-indigo-50 border-indigo-200' },
    'Micro-burst': { icon: Flame, color: 'text-orange-700 bg-orange-50 border-orange-200' },
    'entropy': { icon: BarChart3, color: 'text-teal-700 bg-teal-50 border-teal-200' },
};

function getNovelStyle(factorName) {
    for (const [key, val] of Object.entries(NOVEL_ICONS)) {
        if (factorName.includes(key)) return val;
    }
    return { icon: AlertCircle, color: 'text-blue-700 bg-blue-50 border-blue-200' };
}

export default function UserDetail({ userId, onBack }) {
    const [data, setData] = useState(null);
    const [contagion, setContagion] = useState(null);
    const [showFullNarrative, setShowFullNarrative] = useState(false);
    const [showAllFactors, setShowAllFactors] = useState(false);
    const [showAllActivities, setShowAllActivities] = useState(false);

    useEffect(() => {
        api.getUserDetail(userId).then(setData).catch(console.error);
        fetch(`/api/contagion/${userId}`).then(r => r.json()).then(setContagion).catch(() => { });
    }, [userId]);

    if (!data) return <div className="text-slate-400 py-10 text-center">Loading user details...</div>;

    const { user, current_risk: risk, recent_activities: activities, alerts } = data;

    const novelFactors = (risk.contributing_factors || []).filter(f =>
        Object.keys(NOVEL_ICONS).some(k => f.factor.includes(k))
    );
    const coreFactors = (risk.contributing_factors || []).filter(f =>
        !f.factor.startsWith('Peer deviation') && !Object.keys(NOVEL_ICONS).some(k => f.factor.includes(k))
    );
    const visibleCoreFactors = showAllFactors ? coreFactors : coreFactors.slice(0, 5);

    const anomalousActivities = activities.filter(a => a.is_anomalous);
    const visibleActivities = showAllActivities ? anomalousActivities.slice(0, 30) : anomalousActivities.slice(0, 8);

    const narrativeShort = risk.narrative ? risk.narrative.slice(0, 200) : '';
    const narrativeLong = risk.narrative && risk.narrative.length > 200;

    return (
        <div className="space-y-6 max-w-5xl mx-auto">
            <div className="flex items-center justify-between">
                <button onClick={onBack} className="flex items-center gap-2 text-sm text-slate-500 hover:text-slate-800 transition cursor-pointer">
                    <ArrowLeft className="w-4 h-4" /> Back to Users
                </button>
                <button onClick={() => window.open(`/api/report/${userId}`, '_blank')} className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-xl hover:bg-blue-700 transition text-sm font-medium cursor-pointer shadow-sm">
                    <Download className="w-4 h-4" /> Download Report
                </button>
            </div>

            {/* User Profile Header */}
            <div className="bg-white rounded-2xl border border-slate-200 p-6">
                <div className="flex items-center gap-6">
                    <RiskGauge score={risk.score} level={risk.level} size={100} />
                    <div className="flex-1">
                        <h2 className="text-xl font-bold text-slate-900">{user.full_name}</h2>
                        <p className="text-sm text-slate-500">@{user.username}</p>
                        <div className="flex flex-wrap items-center gap-2 mt-3">
                            <span className="text-xs px-2.5 py-1 rounded-lg bg-blue-50 text-blue-700 font-medium border border-blue-200">{user.department}</span>
                            <span className="text-xs px-2.5 py-1 rounded-lg bg-slate-100 text-slate-600 font-medium">{user.role}</span>
                            <span className="text-xs text-slate-400 flex items-center gap-1"><Clock className="w-3 h-3" /> {user.typical_login_hour}:00</span>
                            <span className="text-xs text-slate-400 flex items-center gap-1"><MapPin className="w-3 h-3" /> {user.typical_location}</span>
                            <span className={`text-xs font-medium flex items-center gap-1 ${data.session_state === 'active' ? 'text-emerald-600' : 'text-red-600'}`}>
                                {data.session_state === 'active' ? <ShieldCheck className="w-3 h-3" /> : <ShieldX className="w-3 h-3" />}
                                {data.session_state}
                            </span>
                        </div>
                    </div>
                    <div className="text-right shrink-0">
                        <p className="text-xs text-slate-400 uppercase font-semibold">Action</p>
                        <p className="text-sm text-slate-700 font-medium mt-1">{risk.action_taken}</p>
                    </div>
                </div>
            </div>

            {/* Threat Narrative - Collapsible */}
            {risk.narrative && (
                <div className={`bg-white rounded-2xl border p-5 ${risk.level === 'red' ? 'border-red-200' : risk.level === 'orange' ? 'border-orange-200' : 'border-slate-200'}`}>
                    <h4 className="text-sm font-semibold text-slate-700 mb-2 flex items-center gap-2">
                        <AlertCircle className="w-4 h-4 text-red-500" /> Threat Narrative
                    </h4>
                    <p className="text-sm text-slate-600 leading-relaxed">
                        {showFullNarrative ? risk.narrative : narrativeShort}{narrativeLong && !showFullNarrative && '...'}
                    </p>
                    {narrativeLong && (
                        <button onClick={() => setShowFullNarrative(!showFullNarrative)} className="flex items-center gap-1 text-xs text-blue-600 font-medium mt-2 cursor-pointer hover:text-blue-800">
                            {showFullNarrative ? <><ChevronUp className="w-3 h-3" /> Show less</> : <><ChevronDown className="w-3 h-3" /> Read full narrative</>}
                        </button>
                    )}
                </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Core Contributing Factors */}
                {coreFactors.length > 0 && (
                    <div className="bg-white rounded-2xl border border-slate-200 p-5">
                        <h4 className="text-sm font-semibold text-slate-700 mb-4">Contributing Factors</h4>
                        <div className="space-y-3">
                            {visibleCoreFactors.map((f, i) => (
                                <div key={i}>
                                    <div className="flex items-center justify-between mb-1">
                                        <span className="text-xs text-slate-600 font-medium truncate max-w-[70%]">{f.factor}</span>
                                        <span className="text-xs font-bold text-slate-500">{f.contribution}%</span>
                                    </div>
                                    <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
                                        <div className="h-full bg-gradient-to-r from-blue-400 to-red-400 rounded-full" style={{ width: `${Math.min(f.contribution, 100)}%` }} />
                                    </div>
                                </div>
                            ))}
                        </div>
                        {coreFactors.length > 5 && (
                            <button onClick={() => setShowAllFactors(!showAllFactors)} className="flex items-center gap-1 text-xs text-blue-600 font-medium mt-3 cursor-pointer hover:text-blue-800">
                                {showAllFactors ? <><ChevronUp className="w-3 h-3" /> Show less</> : <><ChevronDown className="w-3 h-3" /> Show all {coreFactors.length} factors</>}
                            </button>
                        )}
                    </div>
                )}

                {/* Novel Detections */}
                {novelFactors.length > 0 && (
                    <div className="bg-white rounded-2xl border border-slate-200 p-5">
                        <h4 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2">
                            <Eye className="w-4 h-4 text-blue-600" /> AI Engine Detections
                            <span className="text-[9px] px-2 py-0.5 rounded-full bg-blue-100 text-blue-700 font-bold border border-blue-200">{novelFactors.length} triggered</span>
                        </h4>
                        <div className="space-y-2">
                            {novelFactors.map((f, i) => {
                                const { icon: Ico, color } = getNovelStyle(f.factor);
                                return (
                                    <div key={i} className={`flex items-center gap-3 px-3 py-2.5 rounded-xl border ${color}`}>
                                        <Ico className="w-4 h-4 shrink-0" />
                                        <span className="text-xs font-medium flex-1 truncate">{f.factor}</span>
                                        <span className="text-xs font-bold shrink-0">{f.value}</span>
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                )}
            </div>

            {/* Alerts - Compact */}
            {alerts.length > 0 && (
                <div className="bg-white rounded-2xl border border-slate-200 p-5">
                    <h4 className="text-sm font-semibold text-slate-700 mb-3">Alerts ({alerts.length})</h4>
                    <div className="space-y-1.5 max-h-40 overflow-y-auto">
                        {alerts.slice(0, 5).map(a => {
                            const sevColor = a.severity === 'critical' ? 'text-red-600 bg-red-50' : a.severity === 'high' ? 'text-orange-600 bg-orange-50' : 'text-amber-600 bg-amber-50';
                            return (
                                <div key={a.id} className="flex items-center gap-3 text-xs py-1.5">
                                    <span className={`px-2 py-0.5 rounded-md font-bold uppercase ${sevColor}`}>{a.severity}</span>
                                    <span className="flex-1 text-slate-600 truncate">{a.message}</span>
                                    <span className="text-slate-400 shrink-0">{new Date(a.timestamp).toLocaleTimeString()}</span>
                                </div>
                            );
                        })}
                    </div>
                </div>
            )}

            {/* Contagion Network - Compact */}
            {contagion && contagion.connections && contagion.connections.length > 0 && (
                <div className="bg-white rounded-2xl border border-slate-200 p-5">
                    <h4 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2">
                        <Network className="w-4 h-4 text-violet-600" /> Risk Contagion
                        <span className="text-[10px] px-2 py-0.5 rounded-full bg-violet-100 text-violet-700 font-semibold border border-violet-200">NOVEL</span>
                    </h4>
                    <div className="flex flex-wrap gap-2">
                        {contagion.connections.slice(0, 6).map(c => {
                            const dotColor = c.risk_level === 'red' ? 'bg-red-400' : c.risk_level === 'orange' ? 'bg-orange-400' : 'bg-emerald-400';
                            return (
                                <div key={c.user_id} className="flex items-center gap-2 px-3 py-2 rounded-xl bg-slate-50 border border-slate-200 text-xs">
                                    <div className={`w-2 h-2 rounded-full ${dotColor}`} />
                                    <span className="font-medium text-slate-700">{c.full_name}</span>
                                    <span className="text-slate-400">{Math.round(c.risk_score)}</span>
                                </div>
                            );
                        })}
                    </div>
                </div>
            )}

            {/* Activity Log - Anomalous only, compact */}
            {anomalousActivities.length > 0 && (
                <div className="bg-white rounded-2xl border border-slate-200 p-5">
                    <h4 className="text-sm font-semibold text-slate-700 mb-3">
                        Anomalous Activity ({anomalousActivities.length} events)
                    </h4>
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="text-[11px] text-slate-400 uppercase border-b border-slate-100">
                                    <th className="text-left py-2 px-3 font-semibold">Time</th>
                                    <th className="text-left py-2 px-3 font-semibold">Action</th>
                                    <th className="text-left py-2 px-3 font-semibold">Resource</th>
                                    <th className="text-right py-2 px-3 font-semibold">Data</th>
                                </tr>
                            </thead>
                            <tbody>
                                {visibleActivities.map(a => (
                                    <tr key={a.id} className="border-b border-slate-50 hover:bg-slate-50">
                                        <td className="py-2 px-3 text-xs text-slate-500 whitespace-nowrap">{new Date(a.timestamp).toLocaleTimeString()}</td>
                                        <td className={`py-2 px-3 text-xs font-medium ${ACTION_COLORS[a.action_type] || 'text-slate-800'}`}>{a.action_type}</td>
                                        <td className="py-2 px-3 text-xs text-slate-600 font-mono max-w-[200px] truncate">{a.resource}</td>
                                        <td className="py-2 px-3 text-xs text-right text-slate-500">{a.data_volume_mb > 0 ? `${a.data_volume_mb.toFixed(1)} MB` : '-'}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    {anomalousActivities.length > 8 && (
                        <button onClick={() => setShowAllActivities(!showAllActivities)} className="flex items-center gap-1 text-xs text-blue-600 font-medium mt-3 cursor-pointer hover:text-blue-800">
                            {showAllActivities ? <><ChevronUp className="w-3 h-3" /> Show less</> : <><ChevronDown className="w-3 h-3" /> Show all {anomalousActivities.length} anomalous events</>}
                        </button>
                    )}
                </div>
            )}
        </div>
    );
}
