import { BrowserRouter, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import BatchDetail from "./pages/BatchDetail";
import Batches from "./pages/Batches";
import BulkImport from "./pages/BulkImport";
import CodeScanDetail from "./pages/CodeScanDetail";
import CodeScans from "./pages/CodeScans";
import JobDetail from "./pages/JobDetail";
import Jobs from "./pages/Jobs";
import NewCodeScan from "./pages/NewCodeScan";
import NewOrgScan from "./pages/NewOrgScan";
import NewRegistryScan from "./pages/NewRegistryScan";
import NewRuntimeCluster from "./pages/NewRuntimeCluster";
import NewScan from "./pages/NewScan";
import OrgScanDetail from "./pages/OrgScanDetail";
import OrgScans from "./pages/OrgScans";
import RegistryScanDetail from "./pages/RegistryScanDetail";
import RegistryScans from "./pages/RegistryScans";
import RuntimeClusterDetail from "./pages/RuntimeClusterDetail";
import RuntimeClusters from "./pages/RuntimeClusters";

function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<NewScan />} />
          <Route path="/jobs" element={<Jobs />} />
          <Route path="/jobs/:id" element={<JobDetail />} />
          <Route path="/bulk-import" element={<BulkImport />} />
          <Route path="/batches" element={<Batches />} />
          <Route path="/batches/:id" element={<BatchDetail />} />
          <Route path="/org-scans/new" element={<NewOrgScan />} />
          <Route path="/org-scans" element={<OrgScans />} />
          <Route path="/org-scans/:id" element={<OrgScanDetail />} />
          <Route path="/code-scan" element={<NewCodeScan />} />
          <Route path="/code-scans" element={<CodeScans />} />
          <Route path="/code-scans/:id" element={<CodeScanDetail />} />
          <Route path="/registry-scan" element={<NewRegistryScan />} />
          <Route path="/registry-scans" element={<RegistryScans />} />
          <Route path="/registry-scans/:id" element={<RegistryScanDetail />} />
          <Route path="/runtime-defender/new" element={<NewRuntimeCluster />} />
          <Route path="/runtime-clusters" element={<RuntimeClusters />} />
          <Route path="/runtime-clusters/:id" element={<RuntimeClusterDetail />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}

export default App;
