import { NavLink } from 'react-router-dom';
import { useTheme } from '../context/ThemeContext';

export default function Navbar() {
  const { theme, toggleTheme } = useTheme();

  return (
    <header className="navbar">
      <div className="navbar-inner">
        <NavLink to="/" className="navbar-brand">
          <div className="brand-icon">AA</div>
          <span>AccessAtlas</span>
        </NavLink>
        <div className="nav-right">
          <nav>
            <ul className="nav-links">
              <li>
                <NavLink
                  to="/"
                  className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
                  end
                >
                  Overview
                </NavLink>
              </li>
              <li>
                <NavLink
                  to="/findings"
                  className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
                >
                  Findings
                </NavLink>
              </li>
              <li>
                <NavLink
                  to="/evaluation"
                  className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
                >
                  Evaluation
                </NavLink>
              </li>
            </ul>
          </nav>
          <button
            type="button"
            className="theme-toggle-btn"
            onClick={toggleTheme}
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          >
            <span>{theme === 'dark' ? '☀️' : '🌙'}</span>
            <span style={{ fontSize: '0.8rem', textTransform: 'capitalize' }}>
              {theme === 'dark' ? 'Light' : 'Dark'}
            </span>
          </button>
        </div>
      </div>
    </header>
  );
}
