export default function Loading({ message = 'Loading security intelligence data...' }) {
  return (
    <div className="state-container">
      <div className="spinner" />
      <h3 className="state-title">{message}</h3>
      <p className="state-desc">
        The AccessAtlas API loads tabular data and computes privilege models into memory at startup. This may take a few moments.
      </p>
    </div>
  );
}
