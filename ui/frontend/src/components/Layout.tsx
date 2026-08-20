import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";
import Logo from "./Logo";

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <Logo size={30} />
          <div className="sidebar-brand-text">
            ecisp
            <span className="sub">Enterprise Cloud Discovery</span>
          </div>
        </div>
        <NavLink to="/" end className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          New scan
        </NavLink>
        <NavLink to="/jobs" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          Scan history
        </NavLink>
        <div className="nav-section-label">Bulk</div>
        <NavLink to="/bulk-import" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          Import accounts
        </NavLink>
        <NavLink to="/batches" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          Import history
        </NavLink>
        <div className="nav-section-label">Org Security</div>
        <NavLink to="/org-scans/new" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          New org scan
        </NavLink>
        <NavLink to="/org-scans" end className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          Org scan history
        </NavLink>
        <div className="sidebar-footer">
          <a href="https://devopslabinc.com" target="_blank" rel="noreferrer">
            A DevOps Lab product
          </a>
          <span className="sidebar-footer-author">Built by Stan Zvenigorodskiy</span>
        </div>
      </aside>
      <main className="main">{children}</main>
    </div>
  );
}
