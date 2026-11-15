package com.certiverify.core;

import java.time.LocalDateTime;

public class ComplianceEngine {

    public static class AuditResult {
        public String batchId;
        public String supplierName;
        public String parameterName;
        public double measuredValue;
        public double minLimit;
        public double maxLimit;
        public String complianceStatus;
        public String auditTimestamp;

        public AuditResult(String batchId, String supplierName, String parameterName, double measuredValue, double minLimit, double maxLimit) {
            this.batchId = batchId;
            this.supplierName = supplierName;
            this.parameterName = parameterName;
            this.measuredValue = measuredValue;
            this.minLimit = minLimit;
            this.maxLimit = maxLimit;
            this.auditTimestamp = LocalDateTime.now().toString();
            this.complianceStatus = evaluate();
        }

        private String evaluate() {
            if (this.measuredValue >= this.minLimit && this.measuredValue <= this.maxLimit) {
                return "PASS";
            } else {
                return "QUARANTINE";
            }
        }
    }

    public AuditResult processBatchAudit(String batchId, String supplier, String param, double val, double min, double max) {
        AuditResult result = new AuditResult(batchId, supplier, param, val, min, max);
        System.out.println("[JAVA ENTERPRISE CORE] Evaluated Batch: " + result.batchId + " | Status: " + result.complianceStatus);
        return result;
    }

    public static void main(String[] args) {
        ComplianceEngine engine = new ComplianceEngine();
        engine.processBatchAudit("BATCH-2026-001", "Apex Pharma", "Assay Purity", 98.5, 99.0, 100.0);
    }
}
