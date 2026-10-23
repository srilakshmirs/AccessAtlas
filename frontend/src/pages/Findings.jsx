import { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { fetchFindings } from '../api';
import Loading from '../components/Loading';
import ErrorBanner from '../components/ErrorBanner';
import { SeverityBadge } from '../components/Badges';

const ALL_RULES = [
  { value: '', label: 'All Rules' },
  { value: 'behavioural_anomaly', label: 'Behavioural Anomaly (ML)' },
  { value: 'unlinked_account_review', label: 'Unlinked Account Review' },
  { value: 'orphaned_account', label: 'Orphaned Account' },
  { value: 'dormant_admin', label: 'Dormant Admin' },
  { value: 'shadow_admin_privilege', label: 'Shadow Admin Privilege' },
  { value: 'nested_group_escalation', label: 'Nested Group Escalation' },
  { value: 'cross_platform_admin', label: 'Privilege Concentration (Cross-Platform)' },
  { value: 'token_hygiene_violation', label: 'Token Hygiene Violation' },
  { value: 'admin_policy_drift', label: 'Admin Policy Drift' },
];

const SEVERITY_OPTIONS = [
  { value: '', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
];

const PLATFORM_OPTIONS = [
  { value: '', label: 'All Platforms' },
  { value: 'ad', label: 'Active Directory' },
  { value: 'aws', label: 'AWS IAM' },
  { value: 'okta', label: 'Okta' },
];

export default function Findings() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [findingsData, setFindingsData] = useState({ items: [], total: 0, page: 1, size: 25, pages: 1 });

  // Filters
  const [ruleFilter, setRuleFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [platformFilter, setPlatformFilter] = useState('');
  const [identityInput, setIdentityInput] = useState('');
  const [page, setPage] = useState(1);

  // Selected finding for detailed modal
  const [selectedFinding, setSelectedFinding] = useState(null);

  const loadFindings = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await fetchFindings({
        page,
        size: 25,
        rule: ruleFilter || undefined,
        severity: severityFilter || undefined,
        platform: platformFilter || undefined,
        identity_id: identityInput.trim() || undefined,
      });
      setFindingsData(res);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [page, ruleFilter, severityFilter, platformFilter, identityInput]);

  useEffect(() => {
    loadFindings();
  }, [loadFindings]);

  const handleFilterSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    loadFindings();
  };

  const handleResetFilters = () => {
    setRuleFilter('');
    setSeverityFilter('');
    setPlatformFilter('');
    setIdentityInput('');
    setPage(1);
  };

  return (
    <div>
      <div style={{ marginBottom: '1.25rem' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)' }}>
          Security Findings
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
          Deterministic, rule-based IAM risk detections with transparent evidence and confidence caveats.
        </p>
      </div>

      <div className="callout-note">
        <strong>Scope Notice:</strong> Finding counts and table listings cover the entire system snapshot across all splits. The Evaluation page isolates benchmark metrics per specific dataset split (train / test / holdout).
      </div>

      {/* Filter Bar */}
      <form onSubmit={handleFilterSubmit} className="filter-bar">
        <div className="filter-group">
          <label className="filter-label" htmlFor="rule-select">Rule</label>
          <select
            id="rule-select"
            className="filter-select"
            value={ruleFilter}
            onChange={(e) => { setRuleFilter(e.target.value); setPage(1); }}
          >
            {ALL_RULES.map((r) => (
              <option key={r.value} value={r.value}>{r.label}</option>
            ))}
          </select>
        </div>

        <div className="filter-group">
          <label className="filter-label" htmlFor="severity-select">Severity</label>
          <select
            id="severity-select"
            className="filter-select"
            value={severityFilter}
            onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
          >
            {SEVERITY_OPTIONS.map((s) => (
              <option key={s.value} value={s.value}>{s.label}</option>
            ))}
          </select>
        </div>

        <div className="filter-group">
          <label className="filter-label" htmlFor="platform-select">Platform</label>
          <select
            id="platform-select"
            className="filter-select"
            value={platformFilter}
            onChange={(e) => { setPlatformFilter(e.target.value); setPage(1); }}
          >
            {PLATFORM_OPTIONS.map((p) => (
              <option key={p.value} value={p.value}>{p.label}</option>
            ))}
          </select>
        </div>

        <div className="filter-group" style={{ flex: '1 1 200px' }}>
          <label className="filter-label" htmlFor="identity-search">Identity ID</label>
          <input
            id="identity-search"
            type="text"
            className="filter-input"
            placeholder="e.g. E100086 or svc:aws:..."
            value={identityInput}
            onChange={(e) => setIdentityInput(e.target.value)}
          />
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', alignSelf: 'flex-end' }}>
          <button type="submit" className="btn btn-primary">
            Apply
          </button>
          <button type="button" className="btn btn-secondary" onClick={handleResetFilters}>
            Reset
          </button>
        </div>
      </form>

      {error && (
        <ErrorBanner title="Failed to load findings" error={error} onRetry={loadFindings} />
      )}

      {loading ? (
        <Loading message="Filtering and loading findings..." />
      ) : (
        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">
                Showing {findingsData.items.length} of {findingsData.total} Findings
              </h2>
              <p className="card-subtitle">
                Page {findingsData.page} of {findingsData.pages || 1}
              </p>
            </div>
          </div>

          {findingsData.items.length === 0 ? (
            <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
              No findings matched your filter criteria.
            </div>
          ) : (
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Finding ID</th>
                    <th>Rule</th>
                    <th>Severity</th>
                    <th>Platforms</th>
                    <th>Identity</th>
                    <th>Confidence / Caveat</th>
                    <th>Description</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {findingsData.items.map((f) => {
                    const hasCaveat = Boolean(f.confidence_caveat);
                    const firstEvidence = (f.evidence && f.evidence.length > 0)
                      ? f.evidence[0]
                      : (f.recommended_action || '—');

                    return (
                      <tr key={f.finding_id}>
                        <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>{f.finding_id}</td>
                        <td style={{ whiteSpace: 'nowrap' }}>{f.rule.replace(/_/g, ' ')}</td>
                        <td>
                          <SeverityBadge severity={f.severity} />
                        </td>
                        <td>
                          {(f.platforms || []).map((p) => (
                            <span key={p} className="badge badge-platform" style={{ marginRight: '0.25rem' }}>
                              {p}
                            </span>
                          ))}
                        </td>
                        <td>
                          <Link to={`/identities/${encodeURIComponent(f.identity_id)}`} style={{ fontWeight: 600 }}>
                            {f.identity_id}
                          </Link>
                        </td>
                        <td>
                          {hasCaveat ? (
                            <span className="badge badge-caveat" title={f.confidence_caveat}>
                              Caveat: Unresolved Link
                            </span>
                          ) : (
                            <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>Direct Link</span>
                          )}
                        </td>
                        <td
                          style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                          title={firstEvidence}
                        >
                          {firstEvidence}
                        </td>
                        <td>
                          <button
                            type="button"
                            className="btn btn-secondary"
                            style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }}
                            onClick={() => setSelectedFinding(f)}
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination controls */}
          <div className="pagination-bar">
            <span className="pagination-info">
              Page {findingsData.page} of {findingsData.pages || 1} ({findingsData.total} total items)
            </span>
            <div className="pagination-actions">
              <button
                type="button"
                className="btn btn-secondary"
                disabled={findingsData.page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                &larr; Previous
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                disabled={findingsData.page >= findingsData.pages}
                onClick={() => setPage((p) => p + 1)}
              >
                Next &rarr;
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <div
          role="dialog"
          aria-modal="true"
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'var(--modal-backdrop)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '1.5rem',
          }}
          onClick={() => setSelectedFinding(null)}
        >
          <div
            className="card"
            style={{
              maxWidth: 700,
              width: '100%',
              maxHeight: '85vh',
              overflowY: 'auto',
              marginBottom: 0,
              backgroundColor: 'var(--bg-surface)',
              border: '1px solid var(--border-medium)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="card-header">
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: '1.1rem' }}>
                    {selectedFinding.finding_id}
                  </span>
                  <SeverityBadge severity={selectedFinding.severity} />
                </div>
                <h3 style={{ fontSize: '1.1rem', marginTop: '0.4rem', color: 'var(--text-primary)' }}>
                  {selectedFinding.rule.replace(/_/g, ' ')}
                </h3>
              </div>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setSelectedFinding(null)}
              >
                &times; Close
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <strong>Identity: </strong>
                <Link to={`/identities/${encodeURIComponent(selectedFinding.identity_id)}`} style={{ fontWeight: 600 }}>
                  {selectedFinding.identity_id}
                </Link>
              </div>

              {/* Full Evidence Statements List */}
              {selectedFinding.evidence && selectedFinding.evidence.length > 0 && (
                <div>
                  <strong>Evidence Statements:</strong>
                  <ul style={{ marginTop: '0.4rem', paddingLeft: '1.25rem', color: 'var(--text-secondary)' }}>
                    {selectedFinding.evidence.map((item, idx) => (
                      <li key={idx} style={{ marginBottom: '0.35rem' }}>
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {selectedFinding.confidence_caveat && (
                <div style={{
                  backgroundColor: 'var(--badge-caveat-bg)',
                  border: '1px solid var(--badge-caveat-border)',
                  padding: '0.75rem 1rem',
                  borderRadius: 'var(--radius-md)',
                  color: 'var(--badge-caveat-text)',
                  fontSize: '0.875rem'
                }}>
                  <strong>Confidence Caveat: </strong>
                  {selectedFinding.confidence_caveat}
                </div>
              )}

              {selectedFinding.recommended_action && (
                <div style={{
                  backgroundColor: 'var(--status-success-bg)',
                  border: '1px solid var(--status-success-border)',
                  padding: '0.75rem 1rem',
                  borderRadius: 'var(--radius-md)',
                  color: 'var(--status-success-text)',
                  fontSize: '0.875rem'
                }}>
                  <strong>Recommended Remediation: </strong>
                  {selectedFinding.recommended_action}
                </div>
              )}

              {selectedFinding.privilege_path && (
                <div>
                  <strong>Privilege Path: </strong>
                  <div style={{
                    marginTop: '0.4rem',
                    padding: '0.5rem 0.75rem',
                    background: 'var(--bg-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    fontFamily: 'monospace',
                    fontSize: '0.85rem',
                    color: 'var(--text-primary)',
                  }}>
                    {Array.isArray(selectedFinding.privilege_path)
                      ? selectedFinding.privilege_path.join(' -> ')
                      : String(selectedFinding.privilege_path)}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
