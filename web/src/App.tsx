import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Layout } from "./components/layout/Layout";
import { Dashboard } from "./pages/Dashboard";
import { Scan } from "./pages/Scan";
import { History } from "./pages/History";
import { Explorer } from "./pages/Explorer";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan" element={<Scan />} />
          <Route path="/history" element={<History />} />
          <Route path="/explorer" element={<Explorer />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
