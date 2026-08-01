import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import "./index.css";
import { FirewallPage } from "./pages/FirewallPage";
import { AnalyticsPage } from "./pages/AnalyticsPage";
import { CompliancePage } from "./pages/CompliancePage";
import { RedTeamPage } from "./pages/RedTeamPage";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<FirewallPage />} />
        <Route path="/analytics" element={<AnalyticsPage />} />
        <Route path="/redteam" element={<RedTeamPage />} />
        <Route path="/compliance" element={<CompliancePage />} />
        {/* AI Gateway merged into the Firewall page as a route selector. */}
        <Route path="/gateway" element={<Navigate to="/" replace />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  </StrictMode>,
);
