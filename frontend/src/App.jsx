import { useState, useEffect, useCallback } from 'react';
// import { useWebSocket } from './hooks/useWebSocket';
import { api } from './utils/api';
import Dashboard from './components/Dashboard';
import UserList from './components/UserList';
import UserDetail from './components/UserDetail';
import AlertPanel from './components/AlertPanel';
import Analytics from './components/Analytics';
import Sidebar from './components/Sidebar';
import SimulationPanel from './components/SimulationPanel';
import NotificationToast from './components/NotificationToast';

export default function App() {
    const [page, setPage] = useState('dashboard');
    const [selectedUserId, setSelectedUserId] = useState(null);
    const [dashboardData, setDashboardData] = useState(null);
    const [users, setUsers] = useState([]);
    const [alerts, setAlerts] = useState([]);
    const [toasts, setToasts] = useState([]);
    // const { lastMessage, isConnected } = useWebSocket();
    const lastMessage = null;
    const isConnected = false;

    const loadData = useCallback(async () => {
        try {
            const [dash, u, a] = await Promise.all([
                api.getDashboard(), api.getUsers(), api.getAlerts(),
            ]);
            setDashboardData(dash);
            setUsers(u);
            setAlerts(a);
        } catch (e) { console.error('Load error:', e); }
    }, []);

    useEffect(() => { loadData(); }, [loadData]);

    useEffect(() => {
        if (!lastMessage) return;
        if (lastMessage.type === 'risk_update') {
            loadData();
        }
        if (lastMessage.type === 'alert') {
            const d = lastMessage.data;
            setToasts(prev => [...prev, {
                id: Date.now(),
                title: `${d.risk_level.toUpperCase()} ALERT`,
                message: `${d.username} - Risk: ${d.risk_score}`,
                severity: d.risk_level,
            }]);
            loadData();
        }
    }, [lastMessage, loadData]);

    const removeToast = (id) => setToasts(prev => prev.filter(t => t.id !== id));

    const openUser = (userId) => {
        setSelectedUserId(userId);
        setPage('user-detail');
    };

    return (
        <div className="flex h-screen overflow-hidden">
            <Sidebar page={page} setPage={setPage} isConnected={isConnected} />
            <main className="flex-1 overflow-y-auto p-6" style={{ background: 'linear-gradient(135deg, #eef2ff 0%, #f8fafc 40%, #faf5ff 70%, #f0fdf4 100%)' }}>
                {page === 'dashboard' && (
                    <Dashboard data={dashboardData} users={users} onUserClick={openUser} onRefresh={loadData} />
                )}
                {page === 'users' && (
                    <UserList users={users} onUserClick={openUser} />
                )}
                {page === 'user-detail' && selectedUserId && (
                    <UserDetail userId={selectedUserId} onBack={() => setPage('users')} />
                )}
                {/* {page === 'alerts' && (
                    <AlertPanel alerts={alerts} onRefresh={loadData} onUserClick={openUser} />
                )} */}
                {page === 'analytics' && <Analytics onUserClick={openUser} />}
                {page === 'simulate' && <SimulationPanel onRefresh={loadData} />}
            </main>

            <div className="fixed top-4 right-4 z-50 flex flex-col gap-2">
                {toasts.slice(-3).map(t => (
                    <NotificationToast key={t.id} toast={t} onDismiss={() => removeToast(t.id)} />
                ))}
            </div>
        </div>
    );
}
