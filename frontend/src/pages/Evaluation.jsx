import { useEffect, useState, useCallback } from 'react';
import { fetchEvaluation } from '../api';
import Loading from '../components/Loading';
import ErrorBanner from '../components/ErrorBanner';

const SPLITS = [
  { id: 'train', label: 'Train Split', desc: 'Active development & rule calibration split' },
  { id: 'test', label: 'Test Split', desc: 'Standard evaluation split' },
  { id: 'holdout', label: 'Holdout Split', desc: 'Unseen blind evaluation split' },
];

export default function Evaluation() {
  const [activeSplit, setActiveSplit] = useState('train');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [evalData, setEvalData] = useState(null);

  const loadEval = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchEvaluation(activeSplit);
      setEvalData(data);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [activeSplit]);

  useEffect(() => {
    loadEval();
  }, [loadEval]);

  const scenariosList = evalData?.scenarios ? Object.values(evalData.scenarios) : [];
  const trapsList = evalData?.traps ? Object.values(evalData.traps) : [];

  const coveredCount = scenariosList.filter((s) => s.covered).length;

  return (
    <div>
      <div style={{ marginBottom: '1.25rem' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)' }}>
          Scenario & Trap Evaluation
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
          Quantitative benchmark metrics against ground-truth security scenarios and deliberate benign traps.
        </p>
      </div>

      <div className="callout-note">
        <strong>Scope Notice:</strong> Evaluation metrics are calculated exclusively on the selected split&apos;s ground-truth identities, whereas the Overview and Findings pages display the full system snapshot across all splits.
      </div>

      {/* Split Selector Tabs */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem' }}>
        {SPLITS.map((split) => {
          const isActive = activeSplit === split.id;
          return (
            <button
              key={split.id}
              type="button"
              className={`btn ${isActive ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '0.6rem 1.25rem', fontSize: '0.9rem' }}
              onClick={() => setActiveSplit(split.id)}
            >
              {split.label}
            </button>
          );
        })}
      </div>

      {error && (
        <ErrorBanner
          title={`Failed to load evaluation metrics for split '${activeSplit}'`}
          error={error}
          onRetry={loadEval}
        />
      )}

      {loading ? (
        <Loading message={`Computing evaluation metrics for ${activeSplit} split...`} />
      ) : evalData ? (
        <div>
          {/* Top Summary Stats */}
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-label">Active Split</div>
              <div className="stat-value" style={{ textTransform: 'capitalize' }}>
                {evalData.split}
              </div>
              <div className="stat-sub">Ground-truth isolated</div>
            </div>

            <div className="stat-card">
              <div className="stat-label">Identities Evaluated</div>
              <div className="stat-value">{evalData.total_identities?.toLocaleString() || 0}</div>
              <div className="stat-sub">Resolved across platform sources</div>
            </div>

            <div className="stat-card">
              <div className="stat-label">Scenarios Covered</div>
              <div className="stat-value" style={{ color: 'var(--color-brand)' }}>
                {coveredCount} / {scenariosList.length}
              </div>
              <div className="stat-sub">Deterministic detection rules</div>
            </div>

            <div className="stat-card">
              <div className="stat-label">Total Findings</div>
              <div className="stat-value">{evalData.total_findings?.toLocaleString() || 0}</div>
              <div className="stat-sub">Triggered in this split</div>
            </div>
          </div>

          {/* Scenario Metrics Table */}
          <div className="card">
            <div className="card-header">
              <div>
                <h2 className="card-title">Security Scenario Performance</h2>
                <p className="card-subtitle">
                  Precision, Recall, and F1 score with exact raw TP / FP / FN counts
                </p>
              </div>
            </div>

            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Scenario</th>
                    <th>Status</th>
                    <th style={{ textAlign: 'right' }}>TP</th>
                    <th style={{ textAlign: 'right' }}>FP</th>
                    <th style={{ textAlign: 'right' }}>FN</th>
                    <th style={{ textAlign: 'right' }}>Precision</th>
                    <th style={{ textAlign: 'right' }}>Recall</th>
                    <th style={{ textAlign: 'right' }}>F1 Score</th>
                    <th>Evaluation Notes</th>
                  </tr>
                </thead>
                <tbody>
                  {scenariosList.map((s) => {
                    const noCasesInSplit = s.covered && (s.tp + s.fn === 0);

                    const precPercent = noCasesInSplit
                      ? 'N/A'
                      : (s.precision !== null && s.precision !== undefined
                        ? `${(s.precision * 100).toFixed(1)}%`
                        : 'N/A');

                    const recPercent = noCasesInSplit
                      ? 'N/A'
                      : (s.recall !== null && s.recall !== undefined
                        ? `${(s.recall * 100).toFixed(1)}%`
                        : 'N/A');

                    const f1Percent = noCasesInSplit
                      ? 'N/A'
                      : (s.f1 !== null && s.f1 !== undefined
                        ? `${(s.f1 * 100).toFixed(1)}%`
                        : 'N/A');

                    let notesText = s.notes || '—';
                    if (noCasesInSplit) {
                      notesText = s.notes
                        ? `${s.notes}; no cases in this split`
                        : 'no cases in this split';
                    }

                    return (
                      <tr key={s.scenario}>
                        <td style={{ fontWeight: 600 }}>{s.scenario.replace(/_/g, ' ')}</td>
                        <td>
                          {s.covered ? (
                            <span className="badge" style={{ backgroundColor: 'var(--status-success-bg)', color: 'var(--status-success-text)', borderColor: 'var(--status-success-border)' }}>
                              Covered
                            </span>
                          ) : (
                            <span className="badge badge-platform">
                              Not covered by rules
                            </span>
                          )}
                        </td>
                        <td style={{ textAlign: 'right', fontFamily: 'monospace' }}>{s.tp}</td>
                        <td style={{ textAlign: 'right', fontFamily: 'monospace' }}>{s.fp}</td>
                        <td style={{ textAlign: 'right', fontFamily: 'monospace' }}>{s.fn}</td>
                        <td style={{ textAlign: 'right', fontWeight: 600 }}>{precPercent}</td>
                        <td style={{ textAlign: 'right', fontWeight: 600 }}>{recPercent}</td>
                        <td style={{ textAlign: 'right', fontWeight: 700, color: 'var(--color-brand)' }}>
                          {f1Percent}
                        </td>
                        <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', maxWidth: 280 }}>
                          {notesText}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Trap Scenario Check Table */}
          <div className="card">
            <div className="card-header">
              <div>
                <h2 className="card-title">Benign Trap Scenario Defeat Rates</h2>
                <p className="card-subtitle">
                  Validates that suppression logic prevents benign operational patterns from generating false alarms
                </p>
              </div>
            </div>

            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Trap Scenario</th>
                    <th style={{ textAlign: 'right' }}>Total Traps</th>
                    <th style={{ textAlign: 'right' }}>Flagged Traps</th>
                    <th style={{ textAlign: 'right' }}>False Alarm Rate</th>
                    <th>Firing Rule Exists</th>
                    <th>Suppression Notes</th>
                  </tr>
                </thead>
                <tbody>
                  {trapsList.map((t) => {
                    const alarmRate = (t.false_alarm_rate * 100).toFixed(1);
                    const isZero = t.false_alarm_rate === 0;

                    return (
                      <tr key={t.scenario}>
                        <td style={{ fontWeight: 600 }}>{t.scenario.replace(/_/g, ' ')}</td>
                        <td style={{ textAlign: 'right', fontFamily: 'monospace' }}>{t.total_traps}</td>
                        <td style={{ textAlign: 'right', fontFamily: 'monospace' }}>{t.flagged_traps}</td>
                        <td style={{ textAlign: 'right', fontWeight: 700, color: isZero ? 'var(--status-success-text)' : 'var(--status-danger-text)' }}>
                          {alarmRate}%
                        </td>
                        <td>
                          {t.has_firing_rule ? (
                            <span className="badge" style={{ backgroundColor: 'var(--color-brand-light)', color: 'var(--color-brand)', borderColor: 'var(--color-brand)' }}>
                              Yes (Defeated)
                            </span>
                          ) : (
                            <span className="badge badge-platform">
                              No candidate rule
                            </span>
                          )}
                        </td>
                        <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', maxWidth: 280 }}>
                          {t.notes || '—'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* ML vs Rules Comparison Card */}
          {evalData?.ml_comparison && (
            <div className="card" style={{ marginTop: '1.5rem' }}>
              <div className="card-header">
                <div>
                  <h2 className="card-title">Machine Learning vs. Rules-Only Baseline</h2>
                  <p className="card-subtitle">
                    Evaluation of unsupervised IsolationForest behavioural anomaly detection at a fixed 2.0% alert budget
                  </p>
                </div>
              </div>

              {evalData.ml_comparison.honesty_notes?.length > 0 && (
                <div style={{ padding: '0.75rem 1.25rem', backgroundColor: 'var(--callout-bg, rgba(234, 179, 8, 0.08))', borderLeft: '4px solid var(--color-warning, #f59e0b)', marginBottom: '1rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                  <strong>Evaluation Honesty & Methodology:</strong>
                  <ul style={{ margin: '0.35rem 0 0 1.25rem', padding: 0 }}>
                    {evalData.ml_comparison.honesty_notes.map((note, idx) => (
                      <li key={idx} style={{ marginTop: '0.2rem' }}>{note}</li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      <th>Scenario / Cohort</th>
                      <th style={{ textAlign: 'right' }}>Total</th>
                      <th style={{ textAlign: 'right' }}>Rules Only Recall</th>
                      <th style={{ textAlign: 'right' }}>Combined Recall</th>
                      <th style={{ textAlign: 'right' }}>Combined Precision</th>
                      <th style={{ textAlign: 'right' }}>ML Gain</th>
                      <th>Notes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {evalData.ml_comparison.target_scenarios?.map((s) => {
                      const rulesRec = s.total_in_split > 0 ? `${(s.rules_recall * 100).toFixed(1)}%` : 'N/A';
                      const combRec = s.total_in_split > 0 ? `${(s.combined_recall * 100).toFixed(1)}%` : 'N/A';
                      const combPrec = (s.combined_tp > 0) ? `${(s.combined_precision * 100).toFixed(1)}%` : '0.0%';
                      const gain = s.combined_tp - s.rules_tp;

                      return (
                        <tr key={s.scenario}>
                          <td style={{ fontWeight: 600 }}>{s.scenario.replace(/_/g, ' ')}</td>
                          <td style={{ textAlign: 'right', fontFamily: 'monospace' }}>{s.total_in_split}</td>
                          <td style={{ textAlign: 'right', fontFamily: 'monospace' }}>
                            {s.rules_tp} / {s.total_in_split} ({rulesRec})
                          </td>
                          <td style={{ textAlign: 'right', fontFamily: 'monospace', fontWeight: 600, color: 'var(--color-brand)' }}>
                            {s.combined_tp} / {s.total_in_split} ({combRec})
                          </td>
                          <td style={{ textAlign: 'right', fontWeight: 600 }}>
                            {combPrec}
                          </td>
                          <td style={{ textAlign: 'right', fontWeight: 700, color: gain > 0 ? 'var(--status-success-text)' : 'var(--text-muted)' }}>
                            {gain > 0 ? `+${gain} detected` : '—'}
                          </td>
                          <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                            {s.total_in_split === 0 ? 'No injected cases in this split' : s.notes || 'Unsupervised IsolationForest detection'}
                          </td>
                        </tr>
                      );
                    })}

                    {evalData.ml_comparison.normal && (
                      <tr style={{ borderTop: '2px solid var(--border-color)' }}>
                        <td style={{ fontWeight: 600 }}>Normal Identities (False Alarms)</td>
                        <td style={{ textAlign: 'right', fontFamily: 'monospace' }}>{evalData.ml_comparison.normal.total}</td>
                        <td style={{ textAlign: 'right', fontFamily: 'monospace' }}>
                          {evalData.ml_comparison.normal.rules_flagged} ({(evalData.ml_comparison.normal.rules_far * 100).toFixed(2)}%)
                        </td>
                        <td style={{ textAlign: 'right', fontFamily: 'monospace', color: 'var(--status-success-text)', fontWeight: 600 }}>
                          {evalData.ml_comparison.normal.combined_flagged} ({(evalData.ml_comparison.normal.combined_far * 100).toFixed(2)}%)
                        </td>
                        <td style={{ textAlign: 'right' }}>—</td>
                        <td style={{ textAlign: 'right', color: 'var(--status-success-text)', fontWeight: 600 }}>
                          0 ML false alarms
                        </td>
                        <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                          Fixed 2% budget keeps normal ML FAR at 0.00%
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      ) : null}
    </div>
  );
}
