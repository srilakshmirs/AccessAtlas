import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import { fetchHealth, fetchFindings } from '../api';
import { useTheme } from '../context/ThemeContext';
import Loading from '../components/Loading';
import ErrorBanner from '../components/ErrorBanner';
import { SeverityBadge } from '../components/Badges';

const SEVERITY_COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#2563eb',
};

export default function Overview() {
  const { theme } = useTheme();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [health, setHealth] = useState(null);
  const [findings, setFindings] = useState([]);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [hRes, fRes] = await Promise.all([
        fetchHealth(),
        fetchFindings({ size: 500 }),
      ]);
      setHealth(hRes);
      setFindings(fRes.items || []);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  if (loading) {
    return <Loading message="Loading AccessAtlas Overview..." />;
  }

  if (error) {
    return (
      <div style={{ padding: '1rem 0' }}>
        <ErrorBanner title="Could not load system overview" error={error} onRetry={loadData} />
      </div>
    );
  }

  // Aggregate stats
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  const ruleCounts = {};
  const platformCounts = { ad: 0, aws: 0, okta: 0 };

  findings.forEach((f) => {
    const sev = (f.severity || 'low').toLowerCase();
    if (severityCounts[sev] !== undefined) {
      severityCounts[sev] += 1;
    }

    const r = f.rule || 'other';
    ruleCounts[r] = (ruleCounts[r] || 0) + 1;

    (f.platforms || []).forEach((p) => {
      const pl = p.toLowerCase();
      if (platformCounts[pl] !== undefined) {
        platformCounts[pl] += 1;
      }
    });
  });

  const severityPieData = Object.entries(severityCounts).map(([name, value]) => ({
    name: name.toUpperCase(),
    key: name,
    value,
  }));

  const ruleBarData = Object.entries(ruleCounts)
    .map(([rule, count]) => ({
      rule: rule.replace(/_/g, ' '),
      count,
    }))
    .sort((a, b) => b.count - a.count);

  const topPriorityFindings = findings
    .filter((f) => f.severity === 'critical' || f.severity === 'high')
    .slice(0, 5);

  const tooltipStyle = theme === 'dark'
    ? { backgroundColor: '#151d2e', borderColor: '#334155', color: '#f8fafc', borderRadius: '6px' }
    : { backgroundColor: '#ffffff', borderColor: '#e2e8f0', color: '#0f172a', borderRadius: '6px' };

  const axisStroke = theme === 'dark' ? '#94a3b8' : '#64748b';

  return (
    <div>
      <div style={{ marginBottom: '1.25rem' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)' }}>
          Security Overview
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
          High-level posture, active identity counts, and risk distribution across Active Directory, AWS IAM, and Okta.
        </p>
      </div>

      <div className="callout-note">
        <strong>Scope Notice:</strong> Finding counts and posture metrics reflect the entire active directory snapshot across all splits. The Evaluation page isolates benchmark metrics per specific dataset split (train / test / holdout).
      </div>

      {/* Stats Cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Identities</div>
          <div className="stat-value">{health?.identities_count?.toLocaleString() || 0}</div>
          <div className="stat-sub">Resolved across 3 platforms</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Total Findings</div>
          <div className="stat-value">{health?.findings_count?.toLocaleString() || findings.length}</div>
          <div className="stat-sub">Explainable rule detections</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Critical / High Alerts</div>
          <div className="stat-value" style={{ color: 'var(--severity-critical-text)' }}>
            {(severityCounts.critical + severityCounts.high).toLocaleString()}
          </div>
          <div className="stat-sub">Requiring prioritized triage</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Snapshot Date</div>
          <div className="stat-value" style={{ fontSize: '1.4rem', paddingTop: '0.3rem' }}>
            {health?.snapshot_date || '2026-10-12'}
          </div>
          <div className="stat-sub">API v{health?.version || '0.1.0'}</div>
        </div>
      </div>

      {/* Visual Analytics */}
      <div className="charts-grid">
        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Findings by Severity</h2>
              <p className="card-subtitle">Risk proportion across all active findings</p>
            </div>
          </div>
          <div style={{ height: 260, width: '100%' }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityPieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={4}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {severityPieData.map((entry) => (
                    <Cell key={entry.key} fill={SEVERITY_COLORS[entry.key] || '#94a3b8'} />
                  ))}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} />
                <Legend wrapperStyle={{ color: axisStroke }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Findings by Detection Rule</h2>
              <p className="card-subtitle">Distribution of security and posture violations</p>
            </div>
          </div>
          <div style={{ height: 260, width: '100%' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={ruleBarData} layout="vertical" margin={{ left: 40, right: 20 }}>
                <XAxis type="number" stroke={axisStroke} />
                <YAxis dataKey="rule" type="category" tick={{ fontSize: 11, fill: axisStroke }} width={140} stroke={axisStroke} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="count" fill="var(--color-brand)" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Top Priority Alerts preview */}
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Top Priority Findings</h2>
            <p className="card-subtitle">Sample of high and critical severity alerts</p>
          </div>
          <Link to="/findings" className="btn btn-secondary">
            View All Findings &rarr;
          </Link>
        </div>

        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Finding ID</th>
                <th>Rule</th>
                <th>Severity</th>
                <th>Platforms</th>
                <th>Identity</th>
                <th>Description</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {topPriorityFindings.map((f) => {
                const firstEvidence = (f.evidence && f.evidence.length > 0)
                  ? f.evidence[0]
                  : (f.recommended_action || '—');

                return (
                  <tr key={f.finding_id}>
                    <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>{f.finding_id}</td>
                    <td>{f.rule.replace(/_/g, ' ')}</td>
                    <td>
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td>
                      {(f.platforms || []).map((p) => (
                        <span key={p} className="badge badge-platform" style={{ marginRight: '0.3rem' }}>
                          {p}
                        </span>
                      ))}
                    </td>
                    <td>
                      <Link to={`/identities/${encodeURIComponent(f.identity_id)}`} style={{ fontWeight: 600 }}>
                        {f.identity_id}
                      </Link>
                    </td>
                    <td
                      style={{ maxWidth: 350, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                      title={firstEvidence}
                    >
                      {firstEvidence}
                    </td>
                    <td>
                      <Link to={`/identities/${encodeURIComponent(f.identity_id)}`} className="btn btn-secondary" style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}>
                        Inspect
                      </Link>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
