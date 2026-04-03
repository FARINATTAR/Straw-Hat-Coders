import { useEffect } from 'react';
import { X, AlertTriangle, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react';

const SEVERITY_CONFIG = {
  green: { icon: ShieldCheck, bg: 'bg-emerald-50', border: 'border-emerald-200', text: 'text-emerald-700' },
  yellow: { icon: AlertTriangle, bg: 'bg-amber-50', border: 'border-amber-200', text: 'text-amber-700' },
  orange: { icon: ShieldAlert, bg: 'bg-orange-50', border: 'border-orange-200', text: 'text-orange-700' },
  red: { icon: ShieldX, bg: 'bg-red-50', border: 'border-red-200', text: 'text-red-700' },
};

export default function NotificationToast({ toast, onDismiss }) {
  const config = SEVERITY_CONFIG[toast.severity] || SEVERITY_CONFIG.yellow;
  const Icon = config.icon;

  useEffect(() => {
    const timer = setTimeout(onDismiss, 3000);
    return () => clearTimeout(timer);
  }, [onDismiss]);

  return (
    <div className={`animate-slide-in ${config.bg} ${config.border} border rounded-xl p-4 min-w-[320px] max-w-[400px] shadow-lg`}>
      <div className="flex items-start gap-3">
        <Icon className={`w-5 h-5 mt-0.5 shrink-0 ${config.text}`} />
        <div className="flex-1 min-w-0">
          <p className={`text-sm font-semibold ${config.text}`}>{toast.title}</p>
          <p className="text-xs text-slate-600 mt-1 truncate">{toast.message}</p>
        </div>
        <button onClick={onDismiss} className="text-slate-400 hover:text-slate-600 cursor-pointer">
          <X className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}
