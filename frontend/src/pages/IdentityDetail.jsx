import { Fragment, useEffect, useState, useMemo, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ReactFlow, Background, Controls } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { fetchIdentity } from '../api';
import { useTheme } from '../context/ThemeContext';
import Loading from '../components/Loading';
import ErrorBanner from '../components/ErrorBanner';
import { SeverityBadge, TierBadge } from '../components/Badges';
import FindingExplanation from '../components/FindingExplanation';

export default function IdentityDetail() {
  const { id } = useParams();
  const { theme } = useTheme();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [identity, setIdentity] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);

  const loadIdentity = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchIdentity(id);
      setIdentity(data);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    if (id) {
      loadIdentity();
    }
  }, [id, loadIdentity]);

  // Construct React Flow graph from overall_grant_path
  const { nodes, edges, textSteps } = useMemo(() => {
    if (!identity) {
      return { nodes: [], edges: [], textSteps: [] };
    }

    const grantPath = identity.overall_grant_path;
    if (!grantPath || typeof grantPath !== 'string' || grantPath.trim() === '') {
      return { nodes: [], edges: [], textSteps: [] };
    }

    // Split grant path by '->'
    const parts = grantPath.split('->').map((p) => p.trim()).filter(Boolean);
    const fullChain = [identity.identity_id, ...parts];

    // If overall_effective_tier is known, add Tier as the target node
    if (identity.overall_effective_tier !== null && identity.overall_effective_tier !== undefined) {
      fullChain.push(`Effective Tier ${identity.overall_effective_tier}`);
    }

    const isDark = theme === 'dark';

    const flowNodes = fullChain.map((label, idx) => {
      const isStart = idx === 0;
      const isEnd = idx === fullChain.length - 1;

      let bgColor = isDark ? '#151d2e' : '#ffffff';
      let borderColor = isDark ? '#334155' : '#cbd5e1';
      let textColor = isDark ? '#f8fafc' : '#0f172a';

      if (isStart) {
        bgColor = isDark ? '#1e3a8a' : '#eff6ff';
        borderColor = isDark ? '#3b82f6' : '#2563eb';
        textColor = isDark ? '#93c5fd' : '#1d4ed8';
      } else if (isEnd) {
        if (identity.overall_effective_tier === 0) {
          bgColor = isDark ? '#450a0a' : '#fee2e2';
          borderColor = isDark ? '#7f1d1d' : '#fca5a5';
          textColor = isDark ? '#fca5a5' : '#991b1b';
        } else {
          bgColor = isDark ? '#3b0764' : '#ede9fe';
          borderColor = isDark ? '#6b21a8' : '#c4b5fd';
          textColor = isDark ? '#d8b4fe' : '#5b21b6';
        }
      }

      return {
        id: `node-${idx}`,
        position: { x: idx * 220 + 30, y: 70 },
        data: { label },
        style: {
          background: bgColor,
          border: `2px solid ${borderColor}`,
          color: textColor,
          borderRadius: 8,
          padding: '10px 14px',
          fontSize: '12px',
          fontWeight: isStart || isEnd ? 600 : 500,
          boxShadow: isDark ? '0 1px 3px rgba(0,0,0,0.3)' : '0 1px 3px rgba(0,0,0,0.06)',
          width: 170,
          textAlign: 'center',
          wordBreak: 'break-word',
        },
      };
    });

    const flowEdges = [];
    for (let i = 0; i < fullChain.length - 1; i++) {
      flowEdges.push({
        id: `edge-${i}-${i + 1}`,
        source: `node-${i}`,
        target: `node-${i + 1}`,
        animated: Boolean(identity.hidden_escalation),
        style: {
          stroke: identity.hidden_escalation
            ? (isDark ? '#f87171' : '#dc2626')
            : (isDark ? '#60a5fa' : '#2563eb'),
          strokeWidth: 2,
        },
      });
    }

    return { nodes: flowNodes, edges: flowEdges, textSteps: fullChain };
  }, [identity, theme]);

  if (loading) {
    return <Loading message={`Loading details for identity ${id}...`} />;
  }

  if (error) {
    return (
      <div style={{ padding: '1rem 0' }}>
        <ErrorBanner
          title={`Failed to load identity '${id}'`}
          error={error}
          onRetry={loadIdentity}
        />
        <div style={{ marginTop: '1rem' }}>
          <Link to="/findings" className="btn btn-secondary">
            &larr; Back to Findings
          </Link>
        </div>
      </div>
    );
  }

  if (!identity) {
    return null;
  }

  return (
    <div>
      <div style={{ marginBottom: '1.25rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <Link to="/findings" style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            &larr; Back to Findings
          </Link>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: '0.25rem' }}>
            <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {identity.identity_id}
            </h1>
            <span className="badge badge-platform">{identity.identity_kind}</span>
            {identity.hidden_escalation && (
              <span className="badge badge-critical">Hidden Escalation</span>
            )}
          </div>
        </div>
      </div>

      {/* Identity Summary Card */}
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Identity Profile & Platform Accounts</h2>
            <p className="card-subtitle">Linked accounts identified across source systems</p>
          </div>
          <div>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginRight: '0.5rem' }}>
              Overall Effective Tier:
            </span>
            <TierBadge tier={identity.overall_effective_tier} label="Tier" />
          </div>
        </div>

        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Platform</th>
                <th>Linked Account Identifier</th>
                <th>Effective Platform Tier</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Active Directory</strong></td>
                <td style={{ fontFamily: 'monospace' }}>{identity.ad_account_id || '—'}</td>
                <td><TierBadge tier={identity.ad_effective_tier} label="AD Tier" /></td>
              </tr>
              <tr>
                <td><strong>AWS IAM</strong></td>
                <td style={{ fontFamily: 'monospace' }}>{identity.aws_user_id || '—'}</td>
                <td><TierBadge tier={identity.aws_effective_tier} label="AWS Tier" /></td>
              </tr>
              <tr>
                <td><strong>Okta</strong></td>
                <td style={{ fontFamily: 'monospace' }}>{identity.okta_id || '—'}</td>
                <td><TierBadge tier={identity.okta_tier} label="Okta Tier" /></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Privilege Grant Path */}
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Privilege Grant Path</h2>
            <p className="card-subtitle">
              Calculated privilege chain returned by the identity graph model
            </p>
          </div>
          {identity.hidden_escalation && (
            <span className="badge badge-critical">Indirect Escalation Detected</span>
          )}
        </div>

        {textSteps.length > 0 ? (
          <div>
            {/* Text Step Chain */}
            <div>
              <strong style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                Text Chain Representation:
              </strong>
              <div className="text-chain">
                {textSteps.map((step, idx) => (
                  <Fragment key={idx}>
                    <span className="chain-step">{step}</span>
                    {idx < textSteps.length - 1 && <span className="chain-arrow">&rarr;</span>}
                  </Fragment>
                ))}
              </div>
            </div>

            {/* Visual React Flow Graph */}
            <div style={{ marginTop: '1.25rem' }}>
              <strong style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                Visual Graph Flow:
              </strong>
              <div className="flow-container">
                <ReactFlow
                  nodes={nodes}
                  edges={edges}
                  fitView
                  fitViewOptions={{ padding: 0.2 }}
                  zoomOnScroll={false}
                  nodesDraggable={true}
                  nodesConnectable={false}
                >
                  <Background color={theme === 'dark' ? '#334155' : '#cbd5e1'} gap={16} size={1} />
                  <Controls showInteractive={false} />
                </ReactFlow>
              </div>
            </div>
          </div>
        ) : (
          <div style={{
            padding: '1.5rem',
            background: 'var(--bg-subtle)',
            borderRadius: 'var(--radius-md)',
            color: 'var(--text-secondary)',
            fontSize: '0.9rem'
          }}>
            <p><strong>Note:</strong> No explicit multi-hop grant path was returned by <code>/identities/{id}</code>.</p>
            <p style={{ marginTop: '0.35rem', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              This identity either holds standard direct baseline privileges or has not traversed nested groups or role assumptions.
            </p>
          </div>
        )}
      </div>

      {/* Associated Findings */}
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Associated Security Findings ({identity.findings?.length || 0})</h2>
            <p className="card-subtitle">Deterministic rules triggered for this identity</p>
          </div>
        </div>

        {(!identity.findings || identity.findings.length === 0) ? (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            No security findings or policy violations detected for this identity.
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
                  <th>Confidence / Caveat</th>
                  <th>Remediation / Evidence</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {identity.findings.map((f) => {
                  const firstEvidence = (f.evidence && f.evidence.length > 0)
                    ? f.evidence[0]
                    : (f.recommended_action || '—');

                  return (
                    <tr key={f.finding_id}>
                      <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>{f.finding_id}</td>
                      <td>{f.rule.replace(/_/g, ' ')}</td>
                      <td><SeverityBadge severity={f.severity} /></td>
                      <td>
                        {(f.platforms || []).map((p) => (
                          <span key={p} className="badge badge-platform" style={{ marginRight: '0.25rem' }}>
                            {p}
                          </span>
                        ))}
                      </td>
                      <td>
                        {f.confidence_caveat ? (
                          <span className="badge badge-caveat" title={f.confidence_caveat}>
                            Caveat: Unresolved Link
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>Direct Link</span>
                        )}
                      </td>
                      <td style={{ fontSize: '0.85rem', maxWidth: 320 }} title={firstEvidence}>
                        {firstEvidence}
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          onClick={() => setSelectedFinding(f)}
                          style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', whiteSpace: 'nowrap' }}
                        >
                          <span>✨</span>
                          <span>Explain in plain English</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Finding Detail / Explanation Modal */}
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
                <span style={{ fontFamily: 'monospace', fontWeight: 600 }}>
                  {identity.identity_id}
                </span>
              </div>

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

              {/* Plain English AI Explanation (M9) */}
              <FindingExplanation findingId={selectedFinding.finding_id} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
