import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import DynamicField from "../components/DynamicField";
import TagInput from "../components/TagInput";
import type { ProviderMeta } from "../types";

export default function NewScan() {
  const navigate = useNavigate();
  const [providers, setProviders] = useState<ProviderMeta[]>([]);
  const [engineAvailable, setEngineAvailable] = useState<boolean | null>(null);
  const [engineError, setEngineError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [providerCode, setProviderCode] = useState<string>("");
  const [authMethod, setAuthMethod] = useState<string>("");
  const [authValues, setAuthValues] = useState<Record<string, unknown>>({});
  const [scopeValues, setScopeValues] = useState<Record<string, unknown>>({});

  const [reportName, setReportName] = useState("");
  const [services, setServices] = useState<string[]>([]);
  const [skippedServices, setSkippedServices] = useState<string[]>([]);
  const [ruleset, setRuleset] = useState("default.json");
  const [maxWorkers, setMaxWorkers] = useState(10);
  const [debug, setDebug] = useState(false);

  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  useEffect(() => {
    api
      .providers()
      .then((list) => {
        setProviders(list);
        if (list.length > 0) {
          setProviderCode(list[0].code);
          setAuthMethod(Object.keys(list[0].authMethods)[0] ?? "");
        }
      })
      .catch((e) => setLoadError(String(e.message ?? e)));
    api
      .health()
      .then((h) => {
        setEngineAvailable(h.engine_available);
        setEngineError(h.engine_error);
      })
      .catch(() => setEngineAvailable(false));
  }, []);

  const provider = useMemo(() => providers.find((p) => p.code === providerCode), [providers, providerCode]);
  const methodMeta = provider?.authMethods[authMethod];

  const selectProvider = (code: string) => {
    setProviderCode(code);
    const p = providers.find((pr) => pr.code === code);
    const firstMethod = p ? Object.keys(p.authMethods)[0] : "";
    setAuthMethod(firstMethod ?? "");
    setAuthValues({});
    setScopeValues({});
  };

  const selectMethod = (method: string) => {
    setAuthMethod(method);
    setAuthValues({});
  };

  const handleSubmit = async () => {
    setSubmitError(null);
    setSubmitting(true);
    try {
      const job = await api.createScan({
        provider: providerCode,
        auth_method: authMethod,
        auth: authValues,
        scope: scopeValues,
        report_name: reportName || undefined,
        services,
        skipped_services: skippedServices,
        ruleset,
        max_workers: maxWorkers || 10,
        debug,
      });
      navigate(`/jobs/${job.id}`);
    } catch (e) {
      setSubmitError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmitting(false);
    }
  };

  if (loadError) {
    return (
      <>
        <div className="page-header">
          <h1>New CSPM Scan</h1>
        </div>
        <div className="banner error">Could not reach the backend at the configured API URL: {loadError}</div>
      </>
    );
  }

  return (
    <>
      <div className="page-header">
        <h1>New CSPM Scan</h1>
        <p>Configure a provider, authenticate, and launch a discovery + rule-evaluation run.</p>
      </div>

      {engineAvailable === false && (
        <div className="banner warning">
          Engine not importable from the backend's interpreter{engineError ? `: ${engineError}` : "."} Scans can be
          queued but will fail until the engine is installed (see ui/backend/requirements.txt).
        </div>
      )}
      {submitError && <div className="banner error">{submitError}</div>}

      <div className="card">
        <h2>Provider</h2>
        <div className="provider-grid">
          {providers.map((p) => (
            <button
              key={p.code}
              type="button"
              className={`provider-tile${p.code === providerCode ? " active" : ""}`}
              onClick={() => selectProvider(p.code)}
            >
              {p.label}
              <span className="code">{p.code}</span>
            </button>
          ))}
        </div>

        {provider && (
          <>
            <h2>Authentication</h2>
            <div className="method-tabs">
              {Object.entries(provider.authMethods).map(([key, meta]) => (
                <button
                  key={key}
                  type="button"
                  className={`method-tab${key === authMethod ? " active" : ""}`}
                  onClick={() => selectMethod(key)}
                >
                  {meta.label}
                </button>
              ))}
            </div>
            {methodMeta && methodMeta.fields.length > 0 ? (
              methodMeta.fields.map((f) => (
                <DynamicField
                  key={f.name}
                  field={f}
                  value={authValues[f.name]}
                  onChange={(name, value) => setAuthValues((prev) => ({ ...prev, [name]: value }))}
                />
              ))
            ) : (
              <p className="help">No credentials required for this mode &mdash; uses ambient/local credentials.</p>
            )}
          </>
        )}
      </div>

      {provider && provider.scopeFields.length > 0 && (
        <div className="card">
          <h2>Scope</h2>
          {provider.scopeFields.map((f) => (
            <DynamicField
              key={f.name}
              field={f}
              value={scopeValues[f.name]}
              onChange={(name, value) => setScopeValues((prev) => ({ ...prev, [name]: value }))}
            />
          ))}
        </div>
      )}

      <div className="card">
        <h2>Run options</h2>
        <div className="field-row">
          <div className="field">
            <label htmlFor="report-name">Report name</label>
            <input
              id="report-name"
              type="text"
              value={reportName}
              onChange={(e) => setReportName(e.target.value)}
              placeholder="auto-generated if left blank"
            />
          </div>
          <div className="field">
            <label htmlFor="ruleset">Ruleset</label>
            <input id="ruleset" type="text" value={ruleset} onChange={(e) => setRuleset(e.target.value)} />
          </div>
        </div>
        <div className="field-row">
          <div className="field">
            <label htmlFor="services-include">Include only services</label>
            <TagInput id="services-include" value={services} onChange={setServices} placeholder="defaults to all" />
          </div>
          <div className="field">
            <label htmlFor="services-skip">Skip services</label>
            <TagInput id="services-skip" value={skippedServices} onChange={setSkippedServices} />
          </div>
        </div>
        <div className="field-row">
          <div className="field">
            <label htmlFor="max-workers">Max workers</label>
            <input
              id="max-workers"
              type="number"
              min={1}
              value={maxWorkers === 0 ? "" : maxWorkers}
              onChange={(e) => setMaxWorkers(e.target.value === "" ? 0 : Number(e.target.value))}
            />
          </div>
          <div className="field checkbox-field" style={{ alignSelf: "flex-end", marginBottom: 14 }}>
            <input id="debug" type="checkbox" checked={debug} onChange={(e) => setDebug(e.target.checked)} />
            <label htmlFor="debug" style={{ margin: 0 }}>
              Verbose/debug logging
            </label>
          </div>
        </div>
      </div>

      <button className="btn primary" onClick={handleSubmit} disabled={submitting || !providerCode}>
        {submitting ? "Launching…" : "Launch scan"}
      </button>
    </>
  );
}
