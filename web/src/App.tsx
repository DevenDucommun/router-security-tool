import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Layout } from "./components/layout/Layout";
import { Dashboard } from "./pages/Dashboard";
import { Scan } from "./pages/Scan";
import { Batch } from "./pages/Batch";
import { History } from "./pages/History";
import { Compare } from "./pages/Compare";
import { Explorer } from "./pages/Explorer";
import { Schedules } from "./pages/Schedules";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan" element={<Scan />} />
          <Route path="/batch" element={<Batch />} />
          <Route path="/schedules" element={<Schedules />} />
          <Route path="/history" element={<History />} />
          <Route path="/history/compare" element={<Compare />} />
          <Route path="/explorer" element={<Explorer />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
