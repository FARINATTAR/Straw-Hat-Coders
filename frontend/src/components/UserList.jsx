import { Search, Filter, ArrowUpRight } from 'lucide-react';
import { useState, useMemo } from 'react';

const LEVEL_STYLE = {
  red:    { dot: 'bg-red-500', glow: 'shadow-red-200', accent: 'border-l-red-500', scoreBg: 'bg-red-50 text-red-700', tag: 'Critical' },
  orange: { dot: 'bg-orange-400', glow: 'shadow-orange-200', accent: 'border-l-orange-400', scoreBg: 'bg-orange-50 text-orange-700', tag: 'High' },
  yellow: { dot: 'bg-amber-400', glow: 'shadow-amber-200', accent: 'border-l-amber-400', scoreBg: 'bg-amber-50 text-amber-700', tag: 'Medium' },
  green:  { dot: 'bg-emerald-400', glow: 'shadow-emerald-200', accent: 'border-l-emerald-400', scoreBg: 'bg-emerald-50 text-emerald-700', tag: 'Low' },
};

const INITIALS_BG = [
  'from-blue-500 to-indigo-600',
  'from-violet-500 to-purple-600',
  'from-cyan-500 to-blue-600',
  'from-rose-500 to-pink-600',
  'from-emerald-500 to-teal-600',
  'from-amber-500 to-orange-600',
];

function getInitials(name) {
  return name.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase();
}

export default function UserList({ users, onUserClick }) {
  const [search, setSearch] = useState('');
  const [deptFilter, setDeptFilter] = useState('all');
  const [levelFilter, setLevelFilter] = useState('all');
  const [showFilters, setShowFilters] = useState(false);

  const departments = useMemo(() => [...new Set(users.map(u => u.department))], [users]);

  const filtered = useMemo(() => {
    return users.filter(u => {
      const matchSearch = u.full_name.toLowerCase().includes(search.toLowerCase()) ||
                          u.username.toLowerCase().includes(search.toLowerCase());
      const matchDept = deptFilter === 'all' || u.department === deptFilter;
      const matchLevel = levelFilter === 'all' || u.risk_level === levelFilter;
      return matchSearch && matchDept && matchLevel;
    });
  }, [users, search, deptFilter, levelFilter]);

  const counts = useMemo(() => ({
    red: users.filter(u => u.risk_level === 'red').length,
    orange: users.filter(u => u.risk_level === 'orange').length,
    yellow: users.filter(u => u.risk_level === 'yellow').length,
    green: users.filter(u => u.risk_level === 'green').length,
  }), [users]);

  return (
    <div className="space-y-5 max-w-5xl mx-auto">
      {/* Header Row */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-900">Users</h2>
          <p className="text-xs text-slate-400 mt-0.5">{users.length} monitored accounts</p>
        </div>
        {/* Level Pills */}
        <div className="flex gap-1.5">
          {(['red', 'orange', 'yellow', 'green']).map(lv => {
            const s = LEVEL_STYLE[lv];
            const active = levelFilter === lv;
            return (
              <button key={lv} onClick={() => setLevelFilter(active ? 'all' : lv)}
                className={`flex items-center gap-1.5 pl-2.5 pr-3 py-1.5 rounded-full text-[11px] font-semibold transition-all cursor-pointer border ${
                  active ? `${s.scoreBg} border-current` : 'bg-white border-slate-200 text-slate-500 hover:border-slate-300'
                }`}>
                <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
                {counts[lv]}
              </button>
            );
          })}
        </div>
      </div>

      {/* Search */}
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-300" />
          <input
            type="text" placeholder="Search users..."
            value={search} onChange={e => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 bg-white border border-slate-200 rounded-xl text-sm text-slate-800 placeholder-slate-300 focus:outline-none focus:border-blue-400 focus:ring-2 focus:ring-blue-50 transition"
          />
        </div>
        <button onClick={() => setShowFilters(!showFilters)}
          className={`px-3.5 rounded-xl border transition cursor-pointer flex items-center gap-2 text-xs font-medium ${showFilters ? 'bg-blue-50 border-blue-200 text-blue-600' : 'bg-white border-slate-200 text-slate-500 hover:border-slate-300'}`}>
          <Filter className="w-3.5 h-3.5" /> Filter
        </button>
      </div>

      {showFilters && (
        <div className="flex gap-2 animate-fade-up">
          <select value={deptFilter} onChange={e => setDeptFilter(e.target.value)}
            className="px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs text-slate-600 focus:outline-none cursor-pointer">
            <option value="all">All Departments</option>
            {departments.map(d => <option key={d} value={d}>{d}</option>)}
          </select>
        </div>
      )}

      {/* User List */}
      <div className="space-y-2">
        {filtered.map((user, i) => {
          const s = LEVEL_STYLE[user.risk_level] || LEVEL_STYLE.green;
          const bgIdx = user.id % INITIALS_BG.length;
          return (
            <button
              key={user.id}
              onClick={() => onUserClick(user.id)}
              className={`w-full flex items-center gap-4 px-4 py-3.5 bg-white rounded-xl border border-slate-200 border-l-[3px] ${s.accent} hover:shadow-md hover:border-slate-300 transition-all cursor-pointer text-left group animate-fade-up`}
              style={{ animationDelay: `${i * 25}ms` }}
            >
              {/* Avatar */}
              <div className={`w-9 h-9 rounded-lg bg-gradient-to-br ${INITIALS_BG[bgIdx]} flex items-center justify-center shrink-0`}>
                <span className="text-[11px] font-bold text-white tracking-wide">{getInitials(user.full_name)}</span>
              </div>

              {/* Name + Meta */}
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-slate-800 truncate group-hover:text-blue-700 transition-colors">
                  {user.full_name}
                </p>
                <p className="text-[11px] text-slate-400 truncate">
                  {user.department} &middot; {user.role}
                </p>
              </div>

              {/* Session Status */}
              {user.session_state === 'terminated' && (
                <span className="text-[10px] px-2 py-0.5 rounded-md bg-red-50 text-red-500 font-semibold border border-red-100 shrink-0">
                  Terminated
                </span>
              )}
              {user.session_state === 'restricted' && (
                <span className="text-[10px] px-2 py-0.5 rounded-md bg-amber-50 text-amber-500 font-semibold border border-amber-100 shrink-0">
                  Restricted
                </span>
              )}

              {/* Score Badge */}
              <div className={`px-2.5 py-1 rounded-lg text-xs font-bold tabular-nums shrink-0 ${s.scoreBg}`}>
                {user.risk_score}
              </div>

              {/* Arrow */}
              <ArrowUpRight className="w-4 h-4 text-slate-300 group-hover:text-blue-500 transition shrink-0" />
            </button>
          );
        })}
      </div>

      {filtered.length === 0 && (
        <div className="py-16 text-center text-sm text-slate-400">No users match your search</div>
      )}
    </div>
  );
}
