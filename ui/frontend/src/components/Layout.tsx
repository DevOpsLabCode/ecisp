import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          ecisp
          <span className="sub">Enterprise Cloud Discovery</span>
        </div>
        <NavLink to="/" end className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          New scan
        </NavLink>
        <NavLink to="/jobs" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          Scan history
        </NavLink>
      </aside>
      <main className="main">{children}</main>
    </div>
  );
}
