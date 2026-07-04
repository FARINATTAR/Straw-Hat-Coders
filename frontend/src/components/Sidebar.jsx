import { Shield, Users, AlertTriangle, BarChart3, Play, LayoutDashboard, X } from 'lucide-react';

const NAV = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'users', label: 'Users', icon: Users },
  { id: 'alerts', label: 'Alerts', icon: AlertTriangle },
  { id: 'analytics', label: 'Analytics', icon: BarChart3 },
  { id: 'simulate', label: 'Simulate', icon: Play },
];

export default function Sidebar({ page, setPage, isOpen, onClose }) {
  return (
    <>
      {/* Mobile backdrop overlay */}
      {isOpen && (
        <div 
          className="fixed inset-0 bg-black/40 backdrop-blur-xs z-30 lg:hidden"
          onClick={onClose}
        />
      )}

      <aside 
        className={`fixed inset-y-0 left-0 w-64 border-r border-slate-200 flex flex-col h-screen shrink-0 z-40 transition-transform duration-300 lg:static lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`} 
        style={{ background: 'linear-gradient(180deg, #eef2ff 0%, #f8fafc 50%, #faf5ff 100%)' }}
      >
        <div className="p-5 border-b border-slate-200 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-600 flex items-center justify-center shadow-md shadow-blue-500/20">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-slate-900 tracking-tight">SussedOut</h1>
              <p className="text-[11px] text-slate-500 font-medium">Zero Trust Security</p>
            </div>
          </div>
          <button 
            onClick={onClose}
            className="lg:hidden p-1.5 rounded-lg text-slate-500 hover:bg-slate-100 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <nav className="flex-1 p-3 space-y-1">
          {NAV.map(item => {
            const Icon = item.icon;
            const active = page === item.id || (page === 'user-detail' && item.id === 'users');
            return (
              <button
                key={item.id}
                onClick={() => {
                  setPage(item.id);
                  onClose();
                }}
                className={`w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
                  active
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
      </aside>
    </>
  );
}

