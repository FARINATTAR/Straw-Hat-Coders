const COLORS = { green: '#16a34a', yellow: '#ca8a04', orange: '#ea580c', red: '#dc2626' };
const BG_COLORS = { green: '#dcfce7', yellow: '#fef9c3', orange: '#ffedd5', red: '#fee2e2' };

export default function RiskGauge({ score, level, size = 120 }) {
  const color = COLORS[level] || COLORS.green;
  const bgRing = BG_COLORS[level] || '#f1f5f9';
  const radius = (size - 12) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;
  const center = size / 2;

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={center} cy={center} r={radius} fill="none" stroke={bgRing} strokeWidth="6" />
        <circle
          cx={center} cy={center} r={radius} fill="none"
          stroke={color} strokeWidth="6" strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={circumference - progress}
          className="transition-all duration-1000 ease-out"
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-2xl font-bold" style={{ color }}>{Math.round(score)}</span>
        <span className="text-[10px] uppercase font-semibold tracking-wider" style={{ color }}>
          {level}
        </span>
      </div>
    </div>
  );
}
