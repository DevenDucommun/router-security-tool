import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { useKeyboardShortcuts } from "../../hooks/useKeyboard";

export function Layout() {
  useKeyboardShortcuts();

  return (
    <div className="flex h-screen overflow-hidden bg-[#0f1117]">
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-6">
        <Outlet />
      </main>
    </div>
  );
}
