import { useState, useEffect, useRef, useCallback } from 'react';
import { TrendingUp, Clock, PieChart as PieIcon, Network, Shield, ArrowUpRight } from 'lucide-react';
import {
    BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
    AreaChart, Area, PieChart, Pie, Cell, RadarChart, Radar, PolarGrid,
    PolarAngleAxis, PolarRadiusAxis,
} from 'recharts';
import { api } from '../utils/api';

const COLORS = ['#3b82f6', '#8b5cf6', '#ec4899', '#10b981', '#f59e0b', '#ef4444'];
const LEVEL_DOT = { red: '#ef4444', orange: '#f97316', yellow: '#eab308', green: '#22c55e' };

const tooltipStyle = {
    contentStyle: { background: '#fff', border: '1px solid #e2e8f0', borderRadius: 10, fontSize: 12, boxShadow: '0 4px 12px rgba(0,0,0,0.05)' },
    labelStyle: { color: '#64748b', fontSize: 11 },
};

function ContagionGraph({ nodes, links }) {
    const canvasRef = useRef(null);
    const animRef = useRef(null);
    const posRef = useRef([]);
    const dragRef = useRef({ active: false, idx: -1 });
    const hoveredRef = useRef(null);
    const [hoveredState, setHoveredState] = useState(null);
    const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });

    const getCanvasCoords = useCallback((e) => {
        const canvas = canvasRef.current;
        if (!canvas) return { x: 0, y: 0 };
        const rect = canvas.getBoundingClientRect();
        return {
            x: (e.clientX - rect.left) * (canvas.width / rect.width),
            y: (e.clientY - rect.top) * (canvas.height / rect.height),
        };
    }, []);

    const findNode = useCallback((mx, my) => {
        for (let i = 0; i < posRef.current.length; i++) {
            const p = posRef.current[i];
            const r = 8 + (p.node.score / 100) * 12;
            const dx = p.x - mx, dy = p.y - my;
            if (dx * dx + dy * dy < (r + 4) * (r + 4)) return i;
        }
        return -1;
    }, []);

    useEffect(() => {
        if (!nodes.length) return;
        const depts = [...new Set(nodes.map(n => n.department))];
        const W = 900, H = 500;
        const cx = W / 2, cy = H / 2;
        posRef.current = nodes.map((n, i) => {
            const deptIdx = depts.indexOf(n.department);
            const angle = (deptIdx / depts.length) * Math.PI * 2 + (i * 0.35);
            const r = 100 + Math.random() * 100;
            return { x: cx + Math.cos(angle) * r, y: cy + Math.sin(angle) * r, vx: 0, vy: 0, node: n, pinned: false };
        });

        const canvas = canvasRef.current;
        if (!canvas) return;
        const ctx = canvas.getContext('2d');

        const linkIdx = links.map(l => ({
            si: nodes.findIndex(n => n.id === l.source),
            ti: nodes.findIndex(n => n.id === l.target),
            similarity: l.similarity || 0,
        })).filter(l => l.si !== -1 && l.ti !== -1);

        function tick() {
            const ps = posRef.current;
            const drag = dragRef.current;
            const hov = hoveredRef.current;
            const isDragging = drag.active && drag.idx >= 0;
            const di = isDragging ? drag.idx : -1;

            for (let i = 0; i < ps.length; i++) {
                for (let j = i + 1; j < ps.length; j++) {
                    const dx = ps[j].x - ps[i].x, dy = ps[j].y - ps[i].y;
                    const d2 = dx * dx + dy * dy;
                    const d = Math.sqrt(d2) || 1;
                    const force = 500 / (d2 + 200);
                    const fx = (dx / d) * force, fy = (dy / d) * force;
                    if (i !== di) { ps[i].vx -= fx; ps[i].vy -= fy; }
                    if (j !== di) { ps[j].vx += fx; ps[j].vy += fy; }
                }
            }

            for (const l of linkIdx) {
                const s = ps[l.si], t = ps[l.ti];
                const dx = t.x - s.x, dy = t.y - s.y;
                const d = Math.sqrt(dx * dx + dy * dy) || 1;
                const pull = (d - 140) * 0.003;
                const fx = (dx / d) * pull, fy = (dy / d) * pull;
                if (l.si !== di) { s.vx += fx; s.vy += fy; }
                if (l.ti !== di) { t.vx -= fx; t.vy -= fy; }
            }

            for (let i = 0; i < ps.length; i++) {
                if (i === di) continue;
                ps[i].vx += (W / 2 - ps[i].x) * 0.0005;
                ps[i].vy += (H / 2 - ps[i].y) * 0.0005;
            }

            for (let i = 0; i < ps.length; i++) {
                if (i === di) { ps[i].vx = 0; ps[i].vy = 0; continue; }
                ps[i].vx *= 0.65;
                ps[i].vy *= 0.65;
                ps[i].x += ps[i].vx;
                ps[i].y += ps[i].vy;
                ps[i].x = Math.max(40, Math.min(W - 40, ps[i].x));
                ps[i].y = Math.max(40, Math.min(H - 40, ps[i].y));
            }

            ctx.clearRect(0, 0, W, H);

            for (const l of linkIdx) {
                const s = ps[l.si], t = ps[l.ti];
                ctx.beginPath();
                ctx.moveTo(s.x, s.y);
                ctx.lineTo(t.x, t.y);
                ctx.strokeStyle = `rgba(148,163,184,${0.1 + l.similarity * 0.3})`;
                ctx.lineWidth = 0.8 + l.similarity * 2;
                ctx.stroke();
            }

            for (let i = 0; i < ps.length; i++) {
                const p = ps[i];
                const r = 8 + (p.node.score / 100) * 12;
                const color = LEVEL_DOT[p.node.level] || '#94a3b8';
                const isDragging = drag.active && drag.idx === i;
                const isHov = hov && hov.id === p.node.id;

                if (isHov || isDragging) {
                    ctx.beginPath();
                    ctx.arc(p.x, p.y, r + 8, 0, Math.PI * 2);
                    ctx.fillStyle = color + '15';
                    ctx.fill();
                }

                ctx.beginPath();
                ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
                ctx.fillStyle = color + '25';
                ctx.fill();
                ctx.strokeStyle = color;
                ctx.lineWidth = isDragging ? 3 : 2;
                ctx.stroke();

                ctx.fillStyle = color;
                ctx.font = `bold ${Math.max(9, r * 0.8)}px Inter, system-ui, sans-serif`;
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(Math.round(p.node.score), p.x, p.y);

                ctx.fillStyle = '#475569';
                ctx.font = '10px Inter, system-ui, sans-serif';
                ctx.textBaseline = 'top';
                ctx.fillText(p.node.name.split(' ')[0], p.x, p.y + r + 4);
            }

            animRef.current = requestAnimationFrame(tick);
        }

        animRef.current = requestAnimationFrame(tick);
        return () => cancelAnimationFrame(animRef.current);
    }, [nodes, links]);

    const handleMouseDown = useCallback((e) => {
        const { x, y } = getCanvasCoords(e);
        const idx = findNode(x, y);
        if (idx !== -1) {
            dragRef.current = { active: true, idx };
            e.preventDefault();
        }
    }, [getCanvasCoords, findNode]);

    const handleMouseMove = useCallback((e) => {
        const { x, y } = getCanvasCoords(e);
        const drag = dragRef.current;

        if (drag.active && drag.idx >= 0 && posRef.current[drag.idx]) {
            posRef.current[drag.idx].x = x;
            posRef.current[drag.idx].y = y;
            canvasRef.current.style.cursor = 'grabbing';
        } else {
            const idx = findNode(x, y);
            canvasRef.current.style.cursor = idx !== -1 ? 'grab' : 'default';
            if (idx !== -1) {
                const node = posRef.current[idx].node;
                hoveredRef.current = node;
                setHoveredState(node);
                const rect = canvasRef.current.getBoundingClientRect();
                setTooltipPos({
                    x: e.clientX - rect.left + 15,
                    y: e.clientY - rect.top - 10,
                });
            } else {
                hoveredRef.current = null;
                setHoveredState(null);
            }
        }
    }, [getCanvasCoords, findNode]);

    const handleMouseUp = useCallback(() => {
        dragRef.current = { active: false, idx: -1 };
        if (canvasRef.current) canvasRef.current.style.cursor = 'default';
    }, []);

    return (
        <div className="relative select-none">
            <canvas ref={canvasRef} width={900} height={500}
                className="w-full h-auto rounded-xl"
                onMouseDown={handleMouseDown}
                onMouseMove={handleMouseMove}
                onMouseUp={handleMouseUp}
                onMouseLeave={() => { handleMouseUp(); hoveredRef.current = null; setHoveredState(null); }}
            />
            {hoveredState && !dragRef.current.active && (
                <div className="absolute bg-white border border-slate-200 rounded-xl px-3.5 py-2.5 shadow-lg text-xs pointer-events-none z-10"
                    style={{ left: tooltipPos.x, top: tooltipPos.y }}>
                    <p className="font-bold text-slate-800">{hoveredState.name}</p>
                    <p className="text-slate-500">{hoveredState.department} &middot; @{hoveredState.username}</p>
                    <p className="font-bold mt-1" style={{ color: LEVEL_DOT[hoveredState.level] }}>Risk Score: {hoveredState.score}/100</p>
                </div>
            )}
        </div>
    );
}

const CustomPieLabel = ({ cx, cy, midAngle, outerRadius, name, percent }) => {
    const RADIAN = Math.PI / 180;
    const r = outerRadius + 22;
    const x = cx + r * Math.cos(-midAngle * RADIAN);
    const y = cy + r * Math.sin(-midAngle * RADIAN);
    if (percent < 0.04) return null;
    return (
        <text x={x} y={y} fill="#475569" textAnchor={x > cx ? 'start' : 'end'} dominantBaseline="central" fontSize={11} fontWeight={500}>
            {name} {(percent * 100).toFixed(0)}%
        </text>
    );
};

export default function Analytics({ onUserClick }) {
    const [data, setData] = useState(null);

    useEffect(() => {
        api.getAnalytics().then(setData).catch(console.error);
    }, []);

    if (!data) return <div className="text-slate-400 py-10 text-center">Loading analytics...</div>;

    const deptData = Object.entries(data.department_risk).map(([dept, score]) => ({ name: dept, risk: score }));
    const actionData = Object.entries(data.action_distribution).map(([name, value]) => ({ name, value }));
    const network = data.contagion_network || { nodes: [], links: [] };

    return (
        <div className="space-y-6 max-w-6xl mx-auto">
            <div>
                <h2 className="text-xl font-bold text-slate-900">Analytics</h2>
                <p className="text-xs text-slate-400 mt-0.5">Threat intelligence &middot; behavioral patterns &middot; network analysis</p>
            </div>

            {/* Row 1: Risk Trend + Hourly Activity */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                <div className="bg-white rounded-2xl border border-slate-200 p-5 animate-fade-up">
                    <h3 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2">
                        <TrendingUp className="w-4 h-4 text-blue-500" /> Risk Score Trend
                    </h3>
                    <ResponsiveContainer width="100%" height={220}>
                        <AreaChart data={data.daily_risk_trend}>
                            <defs>
                                <linearGradient id="avgG" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.12} />
                                    <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
                                </linearGradient>
                                <linearGradient id="maxG" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="0%" stopColor="#ef4444" stopOpacity={0.1} />
                                    <stop offset="100%" stopColor="#ef4444" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                            <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#94a3b8' }} tickFormatter={v => v.slice(5)} />
                            <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} domain={[0, 100]} />
                            <Tooltip {...tooltipStyle} />
                            <Area type="monotone" dataKey="avg_risk" stroke="#3b82f6" fill="url(#avgG)" name="Avg Risk" strokeWidth={2} dot={{ r: 3, fill: '#3b82f6', strokeWidth: 0 }} />
                            <Area type="monotone" dataKey="max_risk" stroke="#ef4444" fill="url(#maxG)" name="Max Risk" strokeWidth={1.5} dot={{ r: 3, fill: '#ef4444', strokeWidth: 0 }} strokeDasharray="4 4" />
                        </AreaChart>
                    </ResponsiveContainer>
                </div>

                <div className="bg-white rounded-2xl border border-slate-200 p-5 animate-fade-up" style={{ animationDelay: '50ms' }}>
                    <h3 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2">
                        <Clock className="w-4 h-4 text-violet-500" /> Activity by Hour
                    </h3>
                    <ResponsiveContainer width="100%" height={220}>
                        <BarChart data={data.hourly_activity} barGap={2}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                            <XAxis dataKey="hour" tick={{ fontSize: 10, fill: '#94a3b8' }} tickFormatter={v => `${v}h`} />
                            <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} />
                            <Tooltip {...tooltipStyle} />
                            <Bar dataKey="total" fill="#3b82f6" radius={[4, 4, 0, 0]} name="Total" opacity={0.7} />
                            <Bar dataKey="anomalous" fill="#ef4444" radius={[4, 4, 0, 0]} name="Anomalous" opacity={0.85} />
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Row 2: Dept Radar + Action Pie */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                <div className="bg-white rounded-2xl border border-slate-200 p-5 animate-fade-up" style={{ animationDelay: '100ms' }}>
                    <h3 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2">
                        <Shield className="w-4 h-4 text-emerald-500" /> Department Risk
                    </h3>
                    <ResponsiveContainer width="100%" height={240}>
                        <RadarChart data={deptData}>
                            <PolarGrid stroke="#e2e8f0" />
                            <PolarAngleAxis dataKey="name" tick={{ fontSize: 11, fill: '#475569', fontWeight: 500 }} />
                            <PolarRadiusAxis tick={{ fontSize: 9, fill: '#94a3b8' }} domain={[0, 100]} />
                            <Radar name="Risk" dataKey="risk" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.12} strokeWidth={2} dot={{ r: 3, fill: '#8b5cf6' }} />
                        </RadarChart>
                    </ResponsiveContainer>
                </div>

                <div className="bg-white rounded-2xl border border-slate-200 p-5 animate-fade-up" style={{ animationDelay: '150ms' }}>
                    <h3 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2">
                        <PieIcon className="w-4 h-4 text-pink-500" /> Action Distribution
                    </h3>
                    <ResponsiveContainer width="100%" height={240}>
                        <PieChart>
                            <Pie data={actionData} cx="50%" cy="50%" innerRadius={55} outerRadius={85} dataKey="value" paddingAngle={3}
                                label={CustomPieLabel} labelLine={{ stroke: '#cbd5e1', strokeWidth: 1 }}>
                                {actionData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                            </Pie>
                            <Tooltip {...tooltipStyle} />
                        </PieChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Row 3: Contagion Network */}
            {network.nodes.length > 0 && (
                <div className="bg-white rounded-2xl border border-slate-200 p-5 animate-fade-up" style={{ animationDelay: '200ms' }}>
                    <h3 className="text-sm font-semibold text-slate-700 mb-2 flex items-center gap-2">
                        <Network className="w-4 h-4 text-violet-500" /> Risk Contagion Network
                        <span className="text-[9px] px-2 py-0.5 rounded-full bg-violet-100 text-violet-700 font-bold border border-violet-200">LIVE</span>
                    </h3>
                    <p className="text-[11px] text-slate-400 mb-3">Nodes = users, size = risk score, edges = shared resource access patterns. Hover for details.</p>
                    <ContagionGraph nodes={network.nodes} links={network.links} />
                    <div className="flex items-center gap-5 mt-3 text-[10px] text-slate-400">
                        {Object.entries(LEVEL_DOT).map(([lv, c]) => (
                            <span key={lv} className="flex items-center gap-1.5">
                                <span className="w-2.5 h-2.5 rounded-full" style={{ background: c }} /> {lv.charAt(0).toUpperCase() + lv.slice(1)}
                            </span>
                        ))}
                        <span className="flex items-center gap-1.5 ml-auto">Lines = shared resource similarity</span>
                    </div>
                </div>
            )}

            {/* Row 4: Top Risky Users */}
            <div className="bg-white rounded-2xl border border-slate-200 p-5 animate-fade-up" style={{ animationDelay: '250ms' }}>
                <h3 className="text-sm font-semibold text-slate-700 mb-4">Highest Risk Users</h3>
                <div className="space-y-2">
                    {(data.top_risky_users || []).map((u, i) => {
                        const color = LEVEL_DOT[u.level] || '#94a3b8';
                        return (
                            <button key={i} onClick={() => onUserClick && onUserClick(u.user_id)}
                                className="w-full flex items-center gap-4 px-4 py-3 rounded-xl bg-slate-50 hover:bg-blue-50 transition cursor-pointer text-left group">
                                <span className="text-sm font-bold text-slate-300 w-5 text-center">#{i + 1}</span>
                                <div className="w-8 h-8 rounded-lg flex items-center justify-center text-white text-xs font-bold" style={{ background: color }}>
                                    {Math.round(u.score)}
                                </div>
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm font-semibold text-slate-800 truncate group-hover:text-blue-700 transition-colors">{u.full_name || u.username}</p>
                                    <p className="text-[11px] text-slate-400">{u.department} &middot; {u.role}</p>
                                </div>
                                <span className="text-xs font-bold uppercase" style={{ color }}>{u.level}</span>
                                <ArrowUpRight className="w-4 h-4 text-slate-300 group-hover:text-blue-500 transition" />
                            </button>
                        );
                    })}
                </div>
            </div>
        </div>
    );
}
