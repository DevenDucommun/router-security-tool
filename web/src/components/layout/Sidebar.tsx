import { NavLink } from "react-router-dom";
import { LayoutDashboard, Scan, History, FolderTree, Shield } from "lucide-react";

const links = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/scan", icon: Scan, label: "Scan" },
  { to: "/history", icon: History, label: "History" },
  { to: "/explorer", icon: FolderTree, label: "Explorer" },
];

export function Sidebar() {
  return (
    <aside className="w-56 bg-gray-900 border-r border-gray-800 flex flex-col min-h-screen">
      <div className="p-4 border-b border-gray-800">
        <div className="flex items-center gap-2">
          <Shield className="w-6 h-6 text-emerald-400" />
          <span className="font-semibold text-sm text-white">Router Security</span>
        </div>
        <span className="text-[10px] text-gray-500 mt-1 block">v1.0.0</span>
      </div>

      <nav className="flex-1 p-2 space-y-1">
        {links.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                isActive
                  ? "bg-emerald-500/10 text-emerald-400 font-medium"
                  : "text-gray-400 hover:text-gray-200 hover:bg-gray-800"
              }`
            }
          >
            <Icon className="w-4 h-4" />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-gray-800 text-[11px] text-gray-600">
        Trusted local network
      </div>
    </aside>
  );
}
