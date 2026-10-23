export default function ErrorBanner({ title = 'Error Loading Data', error, onRetry }) {
  const errorMessage = error?.message || (typeof error === 'string' ? error : 'An unexpected error occurred.');

  return (
    <div className="error-banner">
      <div>
        <div className="error-title">{title}</div>
        <div className="error-desc">{errorMessage}</div>
      </div>
      {onRetry && (
        <button type="button" className="btn btn-secondary" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}
