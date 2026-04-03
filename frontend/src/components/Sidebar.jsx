import { Shield, Users, AlertTriangle, BarChart3, Play, LayoutDashboard, Wifi, WifiOff } from 'lucide-react';

const NAV = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'users', label: 'Users', icon: Users },
    { id: 'alerts', label: 'Alerts', icon: AlertTriangle },
    { id: 'analytics', label: 'Analytics', icon: BarChart3 },
    { id: 'simulate', label: 'Simulate', icon: Play },
];

export default function Sidebar({ page, setPage, isConnected }) {
    return (
        <aside className="w-64 border-r border-slate-200 flex flex-col h-screen shrink-0" style={{ background: 'linear-gradient(180deg, #eef2ff 0%, #f8fafc 50%, #faf5ff 100%)' }}>
            <div className="p-5 border-b border-slate-200">
                <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-600 flex items-center justify-center shadow-md shadow-blue-500/20">
                        <Shield className="w-5 h-5 text-white" />
                    </div>
                    <div>
                        <h1 className="text-lg font-bold text-slate-900 tracking-tight">ZeroMind</h1>
                        <p className="text-[11px] text-slate-500 font-medium">Zero Trust Security</p>
                    </div>
                </div>
            </div>

            <nav className="flex-1 p-3 space-y-1">
                {NAV.map(item => {
                    const Icon = item.icon;
                    const active = page === item.id || (page === 'user-detail' && item.id === 'users');
                    return (
                        <button
                            key={item.id}
                            onClick={() => setPage(item.id)}
                            className={`w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${active
                                    ? 'bg-blue-50 text-blue-700 border border-blue-200 shadow-sm'
                                    : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900 border border-transparent'
                                }`}
                        >
                            <Icon className={`w-4 h-4 ${active ? 'text-blue-600' : ''}`} />
                            {item.label}
                        </button>
                    );
                })}
            </nav>

            <div className="p-4 border-t border-slate-200">
                <div className="flex items-center gap-2 text-xs">
                    {isConnected ? (
                        <><Wifi className="w-3.5 h-3.5 text-emerald-500" /><span className="text-emerald-600 font-medium">Live Connected</span></>
                    ) : (
                        <><WifiOff className="w-3.5 h-3.5 text-red-400" /><span className="text-red-500 font-medium">Disconnected</span></>
                    )}
                </div>
                <p className="text-[10px] text-slate-400 mt-2 font-medium">Straw Hat Coders</p>
            </div>
        </aside>
    );
}
