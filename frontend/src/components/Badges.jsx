export function SeverityBadge({ severity }) {
  const sev = (severity || 'low').toLowerCase();
  return <span className={`badge badge-${sev}`}>{sev}</span>;
}

export function TierBadge({ tier, label = 'Tier' }) {
  if (tier === null || tier === undefined) {
    return <span className="badge" style={{ backgroundColor: '#f1f5f9', color: '#64748b' }}>None</span>;
  }
  const isTier0 = tier === 0;
  return (
    <span className={`badge ${isTier0 ? 'badge-tier-0' : 'badge-tier'}`}>
      {label} {tier}
    </span>
  );
}
