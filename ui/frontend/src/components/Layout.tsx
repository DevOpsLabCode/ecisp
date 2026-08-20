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
            Golem
            <span className="sub">Built to defend what you build</span>
          </div>
        </div>
        <NavLink to="/" end className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          New CSPM Scan
        </NavLink>
        <NavLink to="/jobs" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          Scan history
        </NavLink>
        <div className="nav-section-label">Bulk</div>
        <NavLink to="/bulk-import" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          Import Cloud Accounts
        </NavLink>
        <NavLink to="/batches" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          Cloud Import History
        </NavLink>
        <div className="nav-section-label">Org Security</div>
        <NavLink to="/org-scans/new" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          Scan GitHub Organization
        </NavLink>
        <NavLink to="/org-scans" end className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          GitHub Org Scan History
        </NavLink>
        <div className="nav-section-label">Code Security</div>
        <NavLink to="/code-scan" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          New code scan
        </NavLink>
        <NavLink to="/code-scans" end className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          Code scan history
        </NavLink>
        <div className="nav-section-label">Registry Security</div>
        <NavLink to="/registry-scan" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          New Artifact Registry Scan
        </NavLink>
        <NavLink to="/registry-scans" end className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          Artifact Registry Scan History
        </NavLink>
        <div className="nav-section-label">Runtime Defender</div>
        <NavLink to="/runtime-defender/new" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          Install Golem Defender
        </NavLink>
        <NavLink to="/runtime-clusters" end className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          Kubernetes Clusters
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
