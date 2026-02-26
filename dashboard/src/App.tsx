import React from 'react';
import { Badge } from './components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './components/ui/card';
import { Progress } from './components/ui/progress';
import { Activity, AlertTriangle, CheckCircle2, Shield, ShieldAlert, ShieldCheck, Zap } from 'lucide-react';
import { useWebSocket } from './hooks/useWebSocket';

interface DashboardMetrics {
  current_metrics: {
    security_posture_score: number;
    open_vulnerabilities: number;
    critical_vulnerabilities: number;
    remediation_rate: number;
    mttr_hours: number;
  };
  time_series: any;
  alerts: any[];
  trends: any;
}

export default function App() {
  const [metrics, setMetrics] = React.useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [scanStatus, setScanStatus] = React.useState<{phase: string, message: string} | null>(null);

  const fetchMetrics = async () => {
    try {
      // Use default project ID 1 for demo purposes
      const response = await fetch('http://localhost:8000/api/v1/monitoring/dashboard?project_id=1');
      if (response.ok) {
        const data = await response.json();
        setMetrics(data);
      }
    } catch (error) {
      console.error("Failed to fetch metrics:", error);
    } finally {
      setLoading(false);
    }
  };

  React.useEffect(() => {
    fetchMetrics();
    // Poll every 30s as fallback to WebSocket
    const interval = setInterval(fetchMetrics, 30000);
    return () => clearInterval(interval);
  }, []);

  const { isConnected } = useWebSocket({
    url: 'ws://localhost:8000/api/v1/ws/dashboard',
    onMessage: (data) => {
      console.log("WebSocket message received:", data);
      if (data.type === 'scan_update') {
        setScanStatus({
          phase: data.phase,
          message: data.message
        });
        
        // Refresh metrics when scan completes
        if (data.phase === 'completed') {
          fetchMetrics();
          setTimeout(() => setScanStatus(null), 5000);
        }
      }
    }
  });

  const getPostureColor = (score: number) => {
    if (score >= 90) return 'text-green-500';
    if (score >= 70) return 'text-yellow-500';
    return 'text-red-500';
  };

  if (loading && !metrics) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-background text-foreground">
        <div className="flex flex-col items-center gap-4">
          <Activity className="w-12 h-12 animate-pulse text-primary" />
          <h2 className="text-xl font-semibold tracking-tight">Initializing SecurAI Guardian...</h2>
        </div>
      </div>
    );
  }

  // Fallback default data for UI demonstration if API is unavailable
  const displayMetrics = metrics?.current_metrics || {
    security_posture_score: 87.5,
    open_vulnerabilities: 12,
    critical_vulnerabilities: 0,
    remediation_rate: 94.2,
    mttr_hours: 1.5
  };

  return (
    <div className="min-h-screen bg-background text-foreground p-8">
      <div className="max-w-7xl mx-auto space-y-8">
        
        {/* Header */}
        <header className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-primary" />
            <div>
              <h1 className="text-3xl font-bold tracking-tight">SecurAI Guardian</h1>
              <p className="text-muted-foreground flex items-center gap-2">
                <span className={`flex h-2 w-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-yellow-500'}`}></span>
                System Operational {isConnected ? '(Live)' : '(Polling)'}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <Badge variant="outline" className="px-3 py-1 text-sm border-border">
              v21.0 OMEGA
            </Badge>
            <button className="bg-primary text-primary-foreground hover:bg-primary/90 px-4 py-2 rounded-md font-medium text-sm transition-colors flex items-center gap-2">
              <Zap className="w-4 h-4" />
              Run Full Scan
            </button>
          </div>
        </header>

        {/* Active Scan Indicator */}
        {scanStatus && (
          <div className="bg-secondary border border-border rounded-lg p-4 flex items-center justify-between animate-in fade-in slide-in-from-top-4">
            <div className="flex items-center gap-4">
              <div className="h-4 w-4 rounded-full border-2 border-primary border-t-transparent animate-spin" />
              <div>
                <p className="font-medium text-sm text-foreground uppercase tracking-wider">{scanStatus.phase}</p>
                <p className="text-sm text-muted-foreground">{scanStatus.message}</p>
              </div>
            </div>
            <Badge variant="default" className="animate-pulse">Active</Badge>
          </div>
        )}

        {/* KPI Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Security Posture
              </CardTitle>
              {displayMetrics.security_posture_score >= 90 ? (
                <ShieldCheck className="w-4 h-4 text-green-500" />
              ) : (
                <ShieldAlert className="w-4 h-4 text-yellow-500" />
              )}
            </CardHeader>
            <CardContent>
              <div className={`text-4xl font-bold ${getPostureColor(displayMetrics.security_posture_score)}`}>
                {displayMetrics.security_posture_score.toFixed(1)}
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                +2.4% from last scan
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Critical Vulnerabilities
              </CardTitle>
              <AlertTriangle className={displayMetrics.critical_vulnerabilities > 0 ? "w-4 h-4 text-red-500" : "w-4 h-4 text-green-500"} />
            </CardHeader>
            <CardContent>
              <div className="text-4xl font-bold text-foreground">
                {displayMetrics.critical_vulnerabilities}
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                Requires immediate action
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Auto-Remediation Rate
              </CardTitle>
              <Zap className="w-4 h-4 text-blue-500" />
            </CardHeader>
            <CardContent>
              <div className="text-4xl font-bold text-foreground">
                {displayMetrics.remediation_rate.toFixed(1)}%
              </div>
              <Progress value={displayMetrics.remediation_rate} className="mt-3" />
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Mean Time To Resolve
              </CardTitle>
              <CheckCircle2 className="w-4 h-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-4xl font-bold text-foreground">
                {displayMetrics.mttr_hours.toFixed(1)}h
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                -0.5h from last month
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Detailed Panels */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle>Recent Vulnerabilities</CardTitle>
              <CardDescription>
                Issues detected and analyzed by the multi-agent system.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="flex items-start justify-between p-4 rounded-lg border border-border bg-secondary/50">
                    <div className="flex flex-col gap-1">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold">Improper Authentication Validation</span>
                        <Badge variant="destructive">Critical</Badge>
                      </div>
                      <span className="text-sm text-muted-foreground">auth_service.py:142 • Found 2 hours ago</span>
                    </div>
                    <div className="text-right">
                      <Badge variant="outline" className="border-blue-500/30 text-blue-400 bg-blue-500/10">
                        Auto-Fix Ready
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Compliance Status</CardTitle>
              <CardDescription>
                Regulatory framework adherence.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div>
                  <div className="flex justify-between mb-2">
                    <span className="text-sm font-medium">SOC2</span>
                    <span className="text-sm text-green-500 font-medium">100%</span>
                  </div>
                  <Progress value={100} className="bg-secondary" />
                </div>
                <div>
                  <div className="flex justify-between mb-2">
                    <span className="text-sm font-medium">HIPAA</span>
                    <span className="text-sm text-green-500 font-medium">100%</span>
                  </div>
                  <Progress value={100} className="bg-secondary" />
                </div>
                <div>
                  <div className="flex justify-between mb-2">
                    <span className="text-sm font-medium">GDPR</span>
                    <span className="text-sm text-yellow-500 font-medium">85%</span>
                  </div>
                  <Progress value={85} className="bg-secondary" />
                </div>
                <div>
                  <div className="flex justify-between mb-2">
                    <span className="text-sm font-medium">PCI-DSS</span>
                    <span className="text-sm text-green-500 font-medium">92%</span>
                  </div>
                  <Progress value={92} className="bg-secondary" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
