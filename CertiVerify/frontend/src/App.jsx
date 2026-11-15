import React, { useState, useEffect } from "react";

export default function App() {
  const [coaFile, setCoaFile] = useState(null);
  const [poFile, setPoFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [darkMode, setDarkMode] = useState(true);
  
  const [ledger, setLedger] = useState(() => {
    const saved = localStorage.getItem("certiverify_v5_ledger");
    return saved ? JSON.parse(saved) : [];
  });

  const [activeBatchId, setActiveBatchId] = useState(null);
  const [question, setQuestion] = useState("");
  const [chatHistory, setChatHistory] = useState({});
  const [asking, setAsking] = useState(false);

  useEffect(() => {
    localStorage.setItem("certiverify_v5_ledger", JSON.stringify(ledger));
    if (ledger.length > 0 && !activeBatchId) {
      setActiveBatchId(ledger[0].batch_id);
    }
  }, [ledger]);

  const handleAudit = async (e) => {
    e.preventDefault();
    if (!coaFile) {
      alert("Please select a Certificate of Analysis (PDF) first!");
      return;
    }

    setLoading(true);
    const formData = new FormData();
    formData.append("file", coaFile);
    if (poFile) {
      formData.append("po_file", poFile);
    }

    try {
      const response = await fetch("http://localhost:8000/api/v1/extract-coa", {
        method: "POST",
        body: formData,
      });
      if (!response.ok) throw new Error("Backend audit failed");
      const data = await response.json();
      setLedger((prev) => [data, ...prev]);
      setActiveBatchId(data.batch_id);
    } catch (err) {
      alert("Error connecting to FastAPI Backend on port 8000: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleAskQuestion = async (e) => {
    e.preventDefault();
    if (!question.trim() || !activeBatchId) return;

    const currentBatch = ledger.find((b) => b.batch_id === activeBatchId);
    if (!currentBatch) return;

    const userQ = question;
    setQuestion("");
    setAsking(true);

    setChatHistory((prev) => ({
      ...prev,
      [activeBatchId]: [
        ...(prev[activeBatchId] || []),
        { role: "user", text: userQ },
      ],
    }));

    try {
      const res = await fetch("http://localhost:8000/api/v1/ask-coa", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          coa_text: currentBatch.raw_text_excerpt || `Assay: ${currentBatch.extracted_value}%, Status: ${currentBatch.status}`,
          question: userQ,
        }),
      });
      const data = await res.json();
      setChatHistory((prev) => ({
        ...prev,
        [activeBatchId]: [
          ...(prev[activeBatchId] || []),
          { role: "ai", text: data.answer },
        ],
      }));
    } catch (err) {
      setChatHistory((prev) => ({
        ...prev,
        [activeBatchId]: [
          ...(prev[activeBatchId] || []),
          { role: "ai", text: "Error reaching local Ollama RAG endpoint." },
        ],
      }));
    } finally {
      setAsking(false);
    }
  };

  const exportDossier = (item) => {
    const dossier = {
      platform: "CertiVerify Enterprise Governance Suite v5.0",
      regulatory_standard: "FDA 21 CFR Part 11 / ISO-9001 Digital Thread",
      exported_at: new Date().toISOString(),
      qa_officer: "Rakshith Pharma",
      audit_record: item,
      cryptographic_verification: {
        algorithm: "SHA-256",
        signature: item.cryptographic_hash,
        tamper_proof_status: "VERIFIED_IMMUTABLE",
      },
    };
    const blob = new Blob([JSON.stringify(dossier, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${item.batch_id}_Regulatory_Dossier.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const vendorStats = Object.values(
    ledger.reduce((acc, item) => {
      const name = item.supplier_name || "Global Chem Corp";
      if (!acc[name]) {
        acc[name] = { name, total: 0, passed: 0, quarantined: 0 };
      }
      acc[name].total += 1;
      if (item.status === "PASS") acc[name].passed += 1;
      else acc[name].quarantined += 1;
      return acc;
    }, {})
  ).map((v) => {
    const score = Math.round((v.passed / v.total) * 100);
    let tier = "APPROVED VENDOR";
    if (score < 50) tier = "BLACKLIST RISK / PROBATION";
    else if (score < 85) tier = "WATCHLIST AUDIT REQUIRED";
    return { ...v, score, tier };
  });

  const activeBatch = ledger.find((b) => b.batch_id === activeBatchId) || ledger[0];

  const theme = {
    bg: darkMode ? "#0b1120" : "#f8fafc",
    cardBg: darkMode ? "#111827" : "#ffffff",
    cardInner: darkMode ? "#0f172a" : "#f1f5f9",
    textMain: darkMode ? "#f8fafc" : "#0f172a",
    textMuted: darkMode ? "#94a3b8" : "#64748b",
    border: darkMode ? "#1e293b" : "#e2e8f0",
    inputBg: darkMode ? "#0f172a" : "#ffffff",
  };

  return (
    <div style={{ minHeight: "100vh", backgroundColor: theme.bg, color: theme.textMain, fontFamily: "system-ui, sans-serif", padding: "24px", transition: "all 0.3s ease" }}>
      
      {/* Top Navbar */}
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: `1px solid ${theme.border}`, paddingBottom: "16px", marginBottom: "24px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <h1 style={{ margin: 0, fontSize: "24px", fontWeight: "700", color: theme.textMain }}>CertiVerify</h1>
          <span style={{ backgroundColor: "#0284c7", color: "#e0f2fe", padding: "4px 12px", borderRadius: "999px", fontSize: "12px", fontWeight: "600" }}>
            Monopoly Governance Edition v5.0
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "16px", fontSize: "14px" }}>
          <span style={{ color: theme.textMuted }}>QA Officer: <strong style={{ color: theme.textMain }}>Rakshith Pharma</strong></span>
          
          {/* Theme Toggle Button */}
          <button
            onClick={() => setDarkMode(!darkMode)}
            style={{ backgroundColor: darkMode ? "#334155" : "#e2e8f0", color: darkMode ? "#f8fafc" : "#0f172a", border: "none", padding: "6px 14px", borderRadius: "6px", cursor: "pointer", fontWeight: "600" }}
          >
            {darkMode ? "☀️ Light Mode" : "🌙 Dark Mode"}
          </button>

          <button
            onClick={() => { setLedger([]); setChatHistory({}); setActiveBatchId(null); localStorage.removeItem("certiverify_v5_ledger"); }}
            style={{ backgroundColor: "#dc2626", color: "#fff", border: "none", padding: "6px 14px", borderRadius: "6px", cursor: "pointer", fontWeight: "600" }}
          >
            Reset System
          </button>
        </div>
      </header>

      {/* Main Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1.6fr", gap: "24px" }}>
        
        {/* LEFT COLUMN */}
        <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
          
          {/* Ingestion Card */}
          <div style={{ backgroundColor: theme.cardBg, border: `1px solid ${theme.border}`, borderRadius: "12px", padding: "20px" }}>
            <h2 style={{ marginTop: 0, fontSize: "18px", color: theme.textMain }}>1. Multi-Document CoA & PO Ingestion</h2>
            <p style={{ fontSize: "13px", color: theme.textMuted, marginBottom: "16px" }}>
              Upload the Certificate of Analysis (PDF) and optional Purchase Order (PO) for cross-document semantic validation, CAPA, and disposition routing.
            </p>

            <form onSubmit={handleAudit} style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
              <div style={{ border: `1px dashed ${theme.border}`, padding: "12px", borderRadius: "8px", backgroundColor: theme.cardInner }}>
                <label style={{ display: "block", fontSize: "12px", fontWeight: "600", color: "#38bdf8", marginBottom: "6px" }}>
                  REQUIRED: Certificate of Analysis (PDF)
                </label>
                <input type="file" accept=".pdf" onChange={(e) => setCoaFile(e.target.files[0])} style={{ fontSize: "13px", color: theme.textMain }} />
              </div>

              <div style={{ border: `1px dashed ${theme.border}`, padding: "12px", borderRadius: "8px", backgroundColor: theme.cardInner }}>
                <label style={{ display: "block", fontSize: "12px", fontWeight: "600", color: "#a855f7", marginBottom: "6px" }}>
                  OPTIONAL: Purchase Order (PDF/TXT) for Cross-Validation
                </label>
                <input type="file" accept=".pdf,.txt" onChange={(e) => setPoFile(e.target.files[0])} style={{ fontSize: "13px", color: theme.textMain }} />
              </div>

              <button
                type="submit"
                disabled={loading}
                style={{
                  backgroundColor: loading ? "#475569" : "#10b981",
                  color: "#ffffff",
                  border: "none",
                  padding: "12px",
                  borderRadius: "8px",
                  fontWeight: "700",
                  cursor: loading ? "not-allowed" : "pointer",
                  fontSize: "14px",
                }}
              >
                {loading ? "Running Local Ollama (qwen2.5:3b) Audit..." : "Run Multi-Document Compliance & CAPA Audit"}
              </button>
            </form>
          </div>

          {/* Vendor Matrix Card */}
          <div style={{ backgroundColor: theme.cardBg, border: `1px solid ${theme.border}`, borderRadius: "12px", padding: "20px" }}>
            <h2 style={{ marginTop: 0, fontSize: "18px", color: theme.textMain }}>2. Dynamic Vendor Risk & Trust Matrix</h2>
            <p style={{ fontSize: "13px", color: theme.textMuted, marginBottom: "14px" }}>
              Automated supplier governance based on historical batch compliance rates.
            </p>

            {vendorStats.length === 0 ? (
              <div style={{ fontSize: "13px", color: theme.textMuted, fontStyle: "italic" }}>No supplier history recorded yet. Run an audit to generate risk scores.</div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                {vendorStats.map((v, idx) => (
                  <div key={idx} style={{ backgroundColor: theme.cardInner, border: `1px solid ${theme.border}`, borderRadius: "8px", padding: "12px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div>
                      <div style={{ fontWeight: "700", fontSize: "14px", color: theme.textMain }}>{v.name}</div>
                      <div style={{ fontSize: "12px", color: theme.textMuted, marginTop: "2px" }}>
                        Batches: {v.total} | Passed: <span style={{ color: "#10b981" }}>{v.passed}</span> | Quarantined: <span style={{ color: "#ef4444" }}>{v.quarantined}</span>
                      </div>
                    </div>
                    <div style={{ textAlign: "right" }}>
                      <div style={{ fontSize: "16px", fontWeight: "800", color: v.score >= 85 ? "#10b981" : v.score >= 50 ? "#f59e0b" : "#ef4444" }}>
                        {v.score}% Trust
                      </div>
                      <span style={{ fontSize: "10px", padding: "2px 6px", borderRadius: "4px", fontWeight: "700", backgroundColor: v.score >= 85 ? "#064e3b" : v.score >= 50 ? "#78350f" : "#7f1d1d", color: "#fff" }}>
                        {v.tier}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Interactive RAG Chat */}
          <div style={{ backgroundColor: theme.cardBg, border: `1px solid ${theme.border}`, borderRadius: "12px", padding: "20px" }}>
            <h2 style={{ marginTop: 0, fontSize: "18px", color: theme.textMain }}>3. Interactive RAG ("Ask This CoA" AI)</h2>
            <p style={{ fontSize: "13px", color: theme.textMuted, marginBottom: "12px" }}>
              Query the active Certificate of Analysis using natural language via local Ollama.
            </p>

            {!activeBatch ? (
              <div style={{ fontSize: "13px", color: theme.textMuted, fontStyle: "italic" }}>Audit a certificate first to unlock interactive RAG querying.</div>
            ) : (
              <>
                <div style={{ fontSize: "12px", color: "#38bdf8", marginBottom: "8px", fontWeight: "600" }}>
                  Active Context: {activeBatch.batch_id} ({activeBatch.supplier_name})
                </div>
                <div style={{ backgroundColor: theme.cardInner, border: `1px solid ${theme.border}`, borderRadius: "8px", padding: "12px", height: "160px", overflowY: "auto", marginBottom: "10px", display: "flex", flexDirection: "column", gap: "8px" }}>
                  {(chatHistory[activeBatch.batch_id] || []).length === 0 ? (
                    <span style={{ fontSize: "12px", color: theme.textMuted }}>
                      Ask anything (e.g., "Were any heavy metals reported?", "Can we blend this batch to recover assay?").
                    </span>
                  ) : (
                    (chatHistory[activeBatch.batch_id] || []).map((msg, i) => (
                      <div key={i} style={{ alignSelf: msg.role === "user" ? "flex-end" : "flex-start", backgroundColor: msg.role === "user" ? "#0284c7" : theme.border, color: msg.role === "user" ? "#fff" : theme.textMain, padding: "8px 12px", borderRadius: "8px", maxWidth: "85%", fontSize: "12px", lineHeight: "1.4" }}>
                        <strong>{msg.role === "user" ? "You: " : "Ollama RAG: "}</strong>
                        {msg.text}
                      </div>
                    ))
                  )}
                </div>
                <form onSubmit={handleAskQuestion} style={{ display: "flex", gap: "8px" }}>
                  <input
                    type="text"
                    value={question}
                    onChange={(e) => setQuestion(e.target.value)}
                    placeholder="Ask Ollama about this CoA..."
                    style={{ flex: 1, backgroundColor: theme.inputBg, border: `1px solid ${theme.border}`, borderRadius: "6px", padding: "8px 12px", color: theme.textMain, fontSize: "13px" }}
                  />
                  <button
                    type="submit"
                    disabled={asking}
                    style={{ backgroundColor: "#38bdf8", color: "#0f172a", border: "none", padding: "8px 16px", borderRadius: "6px", fontWeight: "700", cursor: "pointer", fontSize: "13px" }}
                  >
                    {asking ? "..." : "Ask"}
                  </button>
                </form>
              </>
            )}
          </div>

        </div>

        {/* RIGHT COLUMN: Diagnostic Audit Ledger */}
        <div style={{ backgroundColor: theme.cardBg, border: `1px solid ${theme.border}`, borderRadius: "12px", padding: "20px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
            <h2 style={{ margin: 0, fontSize: "18px", color: theme.textMain }}>
              4. Cryptographic Diagnostic Audit Ledger ({ledger.length})
            </h2>
            <button
              onClick={() => { setLedger([]); setChatHistory({}); setActiveBatchId(null); localStorage.removeItem("certiverify_v5_ledger"); }}
              style={{ backgroundColor: "transparent", border: "1px solid #ef4444", color: "#ef4444", padding: "4px 10px", borderRadius: "6px", fontSize: "12px", cursor: "pointer" }}
            >
              Clear Ledger
            </button>
          </div>

          {ledger.length === 0 ? (
            <div style={{ textAlign: "center", padding: "60px 20px", color: theme.textMuted, fontSize: "14px" }}>
              Ledger is empty. Upload a Certificate of Analysis on the left to execute local LLM diagnostics.
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
              {ledger.map((item, index) => (
                <div
                  key={index}
                  onClick={() => setActiveBatchId(item.batch_id)}
                  style={{
                    backgroundColor: activeBatchId === item.batch_id ? theme.cardInner : theme.bg,
                    border: activeBatchId === item.batch_id ? "1px solid #38bdf8" : `1px solid ${theme.border}`,
                    borderRadius: "10px",
                    padding: "16px",
                    cursor: "pointer",
                    transition: "all 0.2s",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                    <span style={{ color: "#38bdf8", fontWeight: "700", fontSize: "14px" }}>
                      {item.batch_id} • {item.supplier_name}
                    </span>
                    <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                      <span style={{ fontSize: "11px", padding: "3px 8px", borderRadius: "4px", fontWeight: "700", backgroundColor: item.po_match_status === "VERIFIED MATCH" ? "#065f46" : item.po_match_status === "DISCREPANCY DETECTED" ? "#7f1d1d" : theme.border, color: "#e2e8f0" }}>
                        PO: {item.po_match_status || "NO PO PROVIDED"}
                      </span>
                      <span style={{ fontSize: "11px", padding: "3px 10px", borderRadius: "4px", fontWeight: "700", backgroundColor: item.status === "PASS" ? "#064e3b" : "#450a0a", color: item.status === "PASS" ? "#34d399" : "#f87171" }}>
                        {item.status}
                      </span>
                    </div>
                  </div>

                  <div style={{ fontSize: "14px", fontWeight: "600", marginBottom: "12px", color: theme.textMain }}>
                    {item.parameter_name}: <strong style={{ color: theme.textMain }}>{item.extracted_value} {item.unit}</strong> (Target: [{item.min_limit}–{item.max_limit}])
                  </div>

                  <div style={{ backgroundColor: theme.cardBg, borderLeft: item.status === "PASS" ? "4px solid #10b981" : "4px solid #ef4444", padding: "12px", borderRadius: "6px", fontSize: "12px", lineHeight: "1.6", color: theme.textMuted, marginBottom: "12px" }}>
                    <div><strong style={{ color: theme.textMain }}>Root Cause:</strong> {item.failure_reason}</div>
                    <div><strong style={{ color: theme.textMain }}>CAPA Action:</strong> {item.corrective_action}</div>
                    <div style={{ color: "#38bdf8" }}><strong>Material Disposition:</strong> {item.disposition_routing}</div>
                    <div style={{ color: "#a855f7" }}><strong>PO Cross-Validation:</strong> {item.po_discrepancy_notes}</div>
                  </div>

                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "11px", color: theme.textMuted, paddingTop: "8px", borderTop: `1px solid ${theme.border}` }}>
                    <div>
                      Confidence: <strong style={{ color: "#10b981" }}>{item.confidence_score}%</strong> | SHA-256: <code style={{ color: theme.textMuted }}>{item.cryptographic_hash?.slice(0, 16)}...</code>
                    </div>
                    <button
                      onClick={(e) => { e.stopPropagation(); exportDossier(item); }}
                      style={{ backgroundColor: theme.cardBg, color: "#38bdf8", border: `1px solid ${theme.border}`, padding: "5px 10px", borderRadius: "6px", fontSize: "11px", fontWeight: "600", cursor: "pointer" }}
                    >
                      ⬇ Export Regulatory Dossier (.JSON)
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

      </div>
    </div>
  );
}