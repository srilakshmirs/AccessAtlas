import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import Navbar from './components/Navbar';
import Overview from './pages/Overview';
import Findings from './pages/Findings';
import IdentityDetail from './pages/IdentityDetail';
import Evaluation from './pages/Evaluation';

export default function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <div className="app-container">
          <Navbar />
          <main className="main-content">
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/identities/:id" element={<IdentityDetail />} />
              <Route path="/evaluation" element={<Evaluation />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </ThemeProvider>
  );
}
