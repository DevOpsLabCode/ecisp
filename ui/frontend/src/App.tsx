import { BrowserRouter, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import BatchDetail from "./pages/BatchDetail";
import Batches from "./pages/Batches";
import BulkImport from "./pages/BulkImport";
import JobDetail from "./pages/JobDetail";
import Jobs from "./pages/Jobs";
import NewScan from "./pages/NewScan";

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
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}

export default App;
