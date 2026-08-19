import { BrowserRouter, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
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
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}

export default App;
