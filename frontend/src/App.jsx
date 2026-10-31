// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { Routes, Route, Navigate } from "react-router-dom";
import SocApp from "./soc/SocApp.jsx";
import RangeApp from "./range/RangeApp.jsx";
import ErrorBoundary from "./ui/ErrorBoundary.jsx";

// Two surfaces sharing one backend: Kaaval SOC (the product) at /, and the
// Range Console (the demo environment) at /range.
export default function App() {
  return (
    <ErrorBoundary>
      <Routes>
        <Route path="/" element={<SocApp />} />
        <Route path="/range" element={<RangeApp />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </ErrorBoundary>
  );
}
