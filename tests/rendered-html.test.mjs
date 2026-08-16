import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

const developmentPreviewMeta =
  /<meta(?=[^>]*\bname=["']codex-preview["'])(?=[^>]*\bcontent=["']development["'])[^>]*>/i;

test("renders development preview metadata", async () => {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  const response = await worker.fetch(
    new Request("http://localhost/", {
      headers: { accept: "text/html" },
    }),
    {
      ASSETS: {
        fetch: async () => new Response("Not found", { status: 404 }),
      },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );

  assert.equal(response.status, 200);
  assert.match(
    response.headers.get("content-type") ?? "",
    /^text\/html\b/i,
  );
  assert.match(await response.text(), developmentPreviewMeta);
});

test("owner and staff accounts have real two-factor and session security", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const cloud = await readFile(new URL("../public/cloud.js", import.meta.url), "utf8");
  const api = await readFile(new URL("../app/api/[[...path]]/route.ts", import.meta.url), "utf8");
  for (const id of ["mfaLoginPanel", "mfaSetupForm", "mfaRecoveryCodes", "securitySessionRows", "securityEventRows", "passwordChangeForm"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /verifyMfa/);
  assert.match(app, /logoutCloud/);
  assert.match(cloud, /security\/mfa\/setup/);
  assert.match(cloud, /security\/sessions\/revoke/);
  assert.match(api, /user_security/);
  assert.match(api, /auth_rate_limits/);
  assert.match(api, /security_events/);
  assert.match(api, /MFA_ENCRYPTION_KEY/);
  assert.match(api, /auth\/mfa\/verify/);
  assert.match(api, /auth\/logout/);
  assert.match(api, /PASSWORD_NOT_STRONG_ENOUGH/);
});

test("sensitive actions use granular cloud permissions and owner approvals", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const cloud = await readFile(new URL("../public/cloud.js", import.meta.url), "utf8");
  const api = await readFile(new URL("../app/api/[[...path]]/route.ts", import.meta.url), "utf8");
  for (const id of ["securityControlCenter", "staffPermissionRows", "securityApprovalRows", "approvalQueueBadge"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(api, /CREATE TABLE IF NOT EXISTS user_permissions/);
  assert.match(api, /CREATE TABLE IF NOT EXISTS approval_requests/);
  assert.match(api, /CUSTOM_PERMISSION_DENIED/);
  assert.match(api, /MFA_REQUIRED_FOR_SENSITIVE_ACTION/);
  assert.match(api, /OWNER_APPROVAL_REQUIRED/);
  assert.match(api, /security\/approvals\/decision/);
  assert.match(cloud, /x-device-name/);
  assert.match(cloud, /getSecurityControlCenter/);
  assert.match(app, /function renderSecurityControls/);
  assert.match(app, /ApprovalDecision/);
});

test("dashboard date windows are locally declared before sync rendering", async () => {
  const source = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  assert.match(source, /const weekAgo=new Date\(today\)/);
  assert.match(source, /weekAgo\.setDate\(weekAgo\.getDate\(\)-7\);const alerts=\[\]/);
  assert.match(source, /tenDaysAgo\.setDate\(tenDaysAgo\.getDate\(\)-9\);const currentEggs=/);
  assert.match(source, /end\.setDate\(end\.getDate\(\)\+days-1\);const endKey=/);
  assert.doesNotMatch(source, /setDate\([^\n]+\),weekAgo=/);
  assert.doesNotMatch(source, /setDate\([^\n]+\),alerts=/);
  assert.doesNotMatch(source, /setDate\([^;\n]+\),[A-Za-z_$][A-Za-z0-9_$]*=/);
});

test("staff access is activated through invitations without the old local-admin bypass", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const api = await readFile(new URL("../app/api/[[...path]]/route.ts", import.meta.url), "utf8");
  assert.match(html, /id="staffActivatePanel"/);
  assert.match(html, /id="staffHome"/);
  assert.doesNotMatch(html, /id="adminBtn"/);
  assert.match(api, /ROLE_PERMISSION_DENIED/);
  assert.match(api, /INVITATION_INVALID_OR_EXPIRED/);
  assert.match(api, /stateForRole/);
  assert.match(html, /id="shareInviteLink"/);
  assert.match(app, /function emptyCloudState/);
  assert.match(app, /currentSession\?\.mode==='local-admin'\?seed:emptyCloudState/);
  assert.match(app, /params\.get\('activate'\)/);
  assert.match(app, /Share activation link/);
  assert.doesNotMatch(app, /currentSession\?\.user\?\.role==='OWNER'\)return seed/);
  assert.match(api, /UPDATE farm_states SET state_json = \?, updated_at = \? WHERE organization_id = \?/);
});

test("live alerts have a synced lifecycle and operations calendar", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const api = await readFile(new URL("../app/api/[[...path]]/route.ts", import.meta.url), "utf8");
  assert.match(html, /id="operations"/);
  assert.match(html, /id="alertCentreRows"/);
  assert.match(html, /id="calendarAgenda"/);
  assert.match(app, /function buildFarmAlerts/);
  assert.match(app, /AlertAction:'alertActions'/);
  assert.match(app, /data-alert-action="RESOLVED"/);
  assert.match(api, /AlertAction: "alertActions"/);
  assert.match(api, /recordOwnedBy\(session, record\)/);
});

test("animal and flock records have live traceability passports", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const worker = await readFile(new URL("../public/sw.js", import.meta.url), "utf8");
  assert.match(html, /id="traceability"/);
  assert.match(html, /id="passportSheet"/);
  assert.match(html, /id="passportBarcode"/);
  assert.match(html, /id="passportTimeline"/);
  assert.match(app, /function renderTraceability/);
  assert.match(app, /function recordTimeline/);
  assert.match(app, /const code39=/);
  assert.match(app, /data-open-passport/);
  assert.match(worker, /farm-manager-v74/);
});

test("veterinary control links schedules, medicine stock, withdrawals and biosecurity", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const api = await readFile(new URL("../app/api/[[...path]]/route.ts", import.meta.url), "utf8");
  const worker = await readFile(new URL("../public/sw.js", import.meta.url), "utf8");
  for (const id of ["medicineForm", "healthProgramForm", "biosecurityForm", "outbreakForm", "withdrawalRows", "mortalityAnalysis"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /function activeWithdrawals/);
  assert.match(app, /function withdrawalFor/);
  assert.match(app, /type:'HEALTH_ISSUE'/);
  assert.match(app, /status:hold\?'WITHHELD':'AVAILABLE'/);
  assert.match(app, /data-release-quarantine/);
  assert.match(app, /HealthProgram:'healthPrograms'/);
  assert.match(api, /HealthProgram: "healthPrograms"/);
  assert.match(api, /DiseaseOutbreak: "outbreaks"/);
  assert.match(worker, /farm-manager-v74/);
});

test("compliance center connects visitors cleaning evidence and inspection packs", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const api = await readFile(new URL("../app/api/[[...path]]/route.ts", import.meta.url), "utf8");
  for (const id of ["compliance", "visitorForm", "sanitationForm", "complianceDocumentForm", "printCompliancePack"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /function complianceStatus/);
  assert.match(app, /queueCreation\('VisitorLog'/);
  assert.match(app, /queueCreation\('SanitationSchedule'/);
  assert.match(app, /queueCreation\('ComplianceDocument'/);
  assert.match(api, /VisitorLog: "visitorLogs"/);
  assert.match(api, /ComplianceDocument: "complianceDocuments"/);
  assert.match(html, /id="complianceDocumentFile"/);
  assert.match(html, /id="complianceDocumentApproved"/);
  assert.match(app, /uploadComplianceFile/);
  assert.match(app, /downloadComplianceFile/);
  assert.match(app, /COMPLIANCE_EVIDENCE_APPROVED/);
  assert.match(api, /DOCUMENT_STORAGE_UNAVAILABLE/);
  assert.match(api, /FILE_TYPE_NOT_ALLOWED/);
  assert.match(api, /compliance\/files/);
});

test("production-to-sale commerce protects stock and tracks customer payments", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const api = await readFile(new URL("../app/api/[[...path]]/route.ts", import.meta.url), "utf8");
  const worker = await readFile(new URL("../public/sw.js", import.meta.url), "utf8");
  for (const id of ["batchForm", "batchCost", "saleLot", "paymentForm", "productLotRows", "sellableStock", "heldStock", "salesWaste", "salesInsights"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /function productionAvailable/);
  assert.match(app, /function liveLotStatus/);
  assert.match(app, /queueCreation\('ProductionLot'/);
  assert.match(app, /queueCreation\('SalePayment'/);
  assert.match(app, /This batch is on a veterinary safety hold/);
  assert.match(app, /Auto-linked from/);
  assert.match(api, /ProductionLot: "productionLots"/);
  assert.match(api, /SalePayment: "salePayments"/);
  assert.match(worker, /farm-manager-v74/);
});

test("financial control derives cash, receivables, payables and budgets from live ledgers", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const api = await readFile(new URL("../app/api/[[...path]]/route.ts", import.meta.url), "utf8");
  const worker = await readFile(new URL("../public/sw.js", import.meta.url), "utf8");
  for (const id of ["finance", "budgetForm", "supplierPaymentForm", "cashAdjustmentForm", "financeLedgerRows", "financeReceivables", "financePayables", "financeForecast"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /function financeCashbook/);
  assert.match(app, /function renderFinance/);
  assert.match(app, /queueCreation\('Budget'/);
  assert.match(app, /queueCreation\('SupplierPayment'/);
  assert.match(app, /queueCreation\('CashAdjustment'/);
  assert.match(api, /SupplierPayment: "supplierPayments"/);
  assert.match(api, /CashAdjustment: "cashAdjustments"/);
  assert.match(api, /Budget: "budgets"/);
  assert.match(worker, /farm-manager-v74/);
});

test("performance intelligence filters live records and exports decision-ready reports", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const worker = await readFile(new URL("../public/sw.js", import.meta.url), "utf8");
  for (const id of ["reportPeriod", "reportFrom", "reportTo", "reportTrendChart", "reportScorecard", "reportCostDrivers", "reportUnitRows", "exportReport"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /function reportWindow/);
  assert.match(app, /function reportRows/);
  assert.match(app, /function renderReports/);
  assert.match(app, /farm-performance-/);
  assert.match(app, /Customer balance due/);
  assert.match(worker, /farm-manager-v74/);
});

test("finance produces a funding-ready printable management statement", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const worker = await readFile(new URL("../public/sw.js", import.meta.url), "utf8");
  for (const id of ["financeStatementForm", "statementPeriod", "statementRecipient", "statementPurpose", "statementRequest", "statementPreparedBy", "statementContact", "statementNote"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /function statementWindow/);
  assert.match(app, /function financeStatementHtml/);
  assert.match(app, /Management Financial Statement/);
  assert.match(app, /not an audited financial statement or bank account statement/);
  assert.match(app, /Net working position/);
  assert.match(app, /Recommended supporting documents/);
  assert.match(app, /filter\(row=>!row\.payrollRecordId\)/);
  assert.match(worker, /farm-manager-v74/);
});

test("financial statement renders directly without popups or embedded frames", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  for (const id of ["statementPreview", "statementDocument", "printFinanceStatement", "closeFinanceStatement"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.doesNotMatch(html, /id="statementFrame"/);
  assert.match(app, /function safeFinanceStatementMarkup\(input\)/);
  assert.match(app, /Array\.isArray\(state\?\.\[key\]\)/);
  assert.match(app, /\$\('#statementDocument'\)\.innerHTML=markup/);
  assert.doesNotMatch(app, /new DOMParser/);
  assert.doesNotMatch(app, /document\.importNode/);
  assert.match(app, /window\.print\(\)/);
  assert.match(app, /function closeFinanceStatement/);
  assert.doesNotMatch(app, /window\.open\('',\s*'_blank',\s*'width=1000,height=900'\)/);
});

test("generated finance statements are saved, cloud synced and reopenable", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const api = await readFile(new URL("../app/api/[[...path]]/route.ts", import.meta.url), "utf8");
  assert.match(html, /id="financeStatementRows"/);
  assert.match(app, /queueCreation\('FinanceStatement',record\)/);
  assert.match(app, /data-reopen-statement/);
  assert.match(app, /FinanceStatement:'financeStatements'/);
  assert.match(api, /FinanceStatement: "financeStatements"/);
});

test("farm intelligence turns accepted live records into actionable synced recommendations", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const api = await readFile(new URL("../app/api/[[...path]]/route.ts", import.meta.url), "utf8");
  const worker = await readFile(new URL("../public/sw.js", import.meta.url), "utf8");
  for (const id of ["intelligence", "intelligenceScore", "intelligenceConfidence", "insightRows", "intelligenceSignals", "insightStatusTabs"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /function buildManagementInsights/);
  assert.match(app, /function renderIntelligence/);
  assert.match(app, /data-insight-action="ACCEPTED"/);
  assert.match(app, /queueCreation\('BIInsightAction',record\)/);
  assert.match(app, /Created from Farm Intelligence/);
  assert.match(api, /BIInsightAction: "insightActions"/);
  assert.match(worker, /farm-manager-v74/);
});

test("farm assistant answers from authorized records and confirms proposals before writes", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const api = await readFile(new URL("../app/api/[[...path]]/route.ts", import.meta.url), "utf8");
  const worker = await readFile(new URL("../public/sw.js", import.meta.url), "utf8");
  for (const id of ["assistant", "assistantMessages", "assistantForm", "assistantQuestion", "assistantPrompts", "assistantCoverage", "assistantMode"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /function farmAssistantAnswer/);
  assert.match(app, /function renderAssistant/);
  assert.match(app, /function askFarmAssistant/);
  assert.match(app, /data-ai-proposal/);
  assert.match(app, /confirm\.dataset\.confirmed!=='true'/);
  assert.match(app, /queueCreation\('AIProposalDecision',record\)/);
  assert.match(app, /AI_PROPOSAL_\$\{decision\}/);
  assert.match(api, /AIProposalDecision: "aiProposalDecisions"/);
  assert.match(worker, /farm-manager-v74/);
});

test("procurement connects smart restocking, approval, inspection, landed cost and assistant guidance", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const api = await readFile(new URL("../app/api/[[...path]]/route.ts", import.meta.url), "utf8");
  const worker = await readFile(new URL("../public/sw.js", import.meta.url), "utf8");
  for (const id of ["requisitionForm", "receiptForm", "restockRows", "requisitionRows", "procurementRestock", "procurementPayable"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /queueCreation\('PurchaseRequisition'/);
  assert.match(app, /queueCreation\('GoodsReceipt'/);
  assert.match(app, /landedCostTotal/);
  assert.match(app, /data-approve-requisition/);
  assert.match(app, /supplier.*purchase.*procure.*quotation.*order/);
  assert.match(api, /PurchaseRequisition: "purchaseRequisitions"/);
  assert.match(api, /GoodsReceipt: "goodsReceipts"/);
  assert.match(worker, /farm-manager-v74/);
});

test("production planning forecasts resources and confirms connected approvals", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const api = await readFile(new URL("../app/api/[[...path]]/route.ts", import.meta.url), "utf8");
  for (const id of ["planning", "productionPlanForm", "planLivePreview", "productionPlanRows", "planningCalendar", "planningAdvice"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /function planningInputs/);
  assert.match(app, /ProductionPlan:'productionPlans'/);
  assert.match(app, /Confirm approval and create records/);
  assert.match(app, /PurchaseRequisition/);
  assert.match(api, /ProductionPlan: "productionPlans"/);
});

test("marketplace reserves cleared stock and connects orders, payments and deliveries", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const api = await readFile(new URL("../app/api/[[...path]]/route.ts", import.meta.url), "utf8");
  for (const id of ["customerOrderForm", "orderLot", "orderPreview", "customerOrderRows", "reservedStock", "orderPipeline", "printCustomerStatement"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /function lotReserved/);
  assert.match(app, /CustomerOrder:'customerOrders'/);
  assert.match(app, /OrderPayment:'orderPayments'/);
  assert.match(app, /Delivery:'deliveries'/);
  assert.match(app, /data-next-status/);
  assert.match(api, /CustomerOrder: "customerOrders"/);
  assert.match(api, /OrderPayment: "orderPayments"/);
  assert.match(api, /Delivery: "deliveries"/);
});

test("sales receipts render as official printable farm invoices", async () => {
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  assert.match(app, /function officialSaleReceiptHtml/);
  assert.match(app, /INVOICE & RECEIPT/);
  assert.match(app, /Official sales document/);
  assert.match(app, /Farm traceability/);
  assert.match(app, /Customer acknowledgement/);
  assert.match(app, /Print \/ Save PDF/);
});

test("sales receipts include QR verification with camera, image and manual scanning", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const pkg = await readFile(new URL("../package.json", import.meta.url), "utf8");
  for (const id of ["openReceiptScanner", "receiptScanner", "receiptScannerVideo", "receiptQrFile", "receiptVerifyCode", "receiptVerificationResult"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /function receiptVerificationCode/);
  assert.match(app, /function parseReceiptCode/);
  assert.match(app, /QRCode\.toDataURL/);
  assert.match(app, /jsQR\(/);
  assert.match(app, /getUserMedia/);
  assert.match(app, /data-verify-sale/);
  assert.match(pkg, /"qrcode"/);
  assert.match(pkg, /"jsqr"/);
  assert.match(app, /from '\.\/qr-tools\.js'/);
  assert.doesNotMatch(app, /from 'qrcode'/);
  assert.doesNotMatch(app, /from 'jsqr'/);
});

test("multi-farm workspaces isolate records and support audited stock transfers", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const api = await readFile(new URL("../app/api/[[...path]]/route.ts", import.meta.url), "utf8");
  assert.match(html, /crossFarmTransferForm/);
  assert.match(html, /teamFarmAccess/);
  assert.match(app, /function blankFarmWorkspace/);
  assert.match(app, /CrossFarmTransfer/);
  assert.match(app, /assignedFarmIds/);
  assert.match(api, /farmWorkspaces/);
  assert.match(api, /CrossFarmTransfer: "crossFarmTransfers"/);
  assert.match(app, /type:'TRANSFER_OUT'/);
  assert.match(app, /inventoryItemId:item\.id/);
  assert.match(app, /quantityDelta:-quantity/);
  assert.match(app, /command\.entityType==='FarmWorkspace'/);
  assert.match(app, /workerFarmAccess/);
  assert.match(api, /configuredFarmIds/);
  assert.match(api, /farmVisible/);
  assert.match(api, /INSERT OR REPLACE INTO farms/);
});

test("stabilization keeps domain changes, farm workspaces, backups and clients in sync", async () => {
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const worker = await readFile(new URL("../public/sw.js", import.meta.url), "utf8");
  assert.match(app, /function queueWorkspaceSnapshot/);
  assert.match(app, /queueCreation\('DailyRecord',record\)/);
  assert.match(app, /queueCreation\('Animal',\{\.\.\.animal\}\)/);
  assert.match(app, /queueCreation\('Task',\{\.\.\.task\}\)/);
  assert.match(app, /mergeCloudSnapshot\(await bootstrap\(\)\)/);
  assert.match(app, /schemaVersion:2/);
  assert.match(app, /\[1,2\]\.includes\(parsed\?\.schemaVersion\)/);
  assert.match(app, /farm-manager-sw-v74/);
  assert.match(app, /sw\.js\?v=74/);
  assert.match(worker, /farm-manager-v74/);
});

test("farm system preference controls poultry, livestock and mixed navigation", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const css = await readFile(new URL("../public/admin.css", import.meta.url), "utf8");
  assert.match(app, /const flockOnlyViews=new Set\(\['flocks'\]\)/);
  assert.match(app, /livestockOnlyViews=new Set\(\['animals','breeding'\]\)/);
  assert.match(app, /function enabledFarmSystems/);
  assert.match(app, /function viewAllowedBySystem/);
  assert.match(app, /buildFarmAlerts\(\)\.filter\(alert=>viewAllowedBySystem\(alert\.view\)\)/);
  assert.match(app, /events\.filter\(event=>viewAllowedBySystem\(event\.view\)\)/);
  assert.match(app, /element\.hidden=!enabled\.has\(element\.dataset\.systemOnly\)/);
  assert.match(html, /data-system-only="FLOCKS"/);
  assert.match(html, /data-system-only="LIVESTOCK"/);
  assert.match(css, /high-legibility interface/);
  assert.match(css, /body\[data-farm-system="mixed"\]/);
});

test("workflow performance renders only the active screen and coalesces workspace snapshots", async () => {
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const store = await readFile(new URL("../public/store.js", import.meta.url), "utf8");
  const worker = await readFile(new URL("../public/sw.js", import.meta.url), "utf8");
  assert.match(app, /const viewRenderers=/);
  assert.match(app, /function renderView\(name=activeView\)/);
  assert.match(app, /renderFrame=requestAnimationFrame\(render\)/);
  assert.match(app, /function scheduleWorkspaceSnapshot/);
  assert.match(app, /queueMicrotask\(/);
  assert.match(store, /let dbPromise/);
  assert.match(store, /let writeQueue = Promise\.resolve\(\)/);
  assert.match(worker, /farm-manager-v74/);
});

test("quick farm entry batches flock and livestock work with safe reversals", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const css = await readFile(new URL("../public/admin.css", import.meta.url), "utf8");
  for (const id of ["quickTarget", "quickMortality", "quickProduction", "quickFeed", "quickWater", "quickHealth", "quickExpense", "quickSale", "useYesterday", "quickChecklist", "quickBatchRows"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /function renderQuickEntry/);
  assert.match(app, /entryMode:'QUICK'/);
  assert.match(app, /data-undo-quick/);
  assert.match(app, /QUICK_ENTRY_BATCH_REVERSED/);
  assert.match(app, /FlockPopulationReversal/);
  assert.match(app, /StockMovementReversal/);
  assert.match(css, /one-screen quick farm entry/);
});

test("operations alerts become assigned auditable tasks with completion evidence", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const css = await readFile(new URL("../public/admin.css", import.meta.url), "utf8");
  const worker = await readFile(new URL("../public/sw.js", import.meta.url), "utf8");
  assert.match(html, /id="briefingHeadline"/);
  assert.match(html, /data-task-filter="OVERDUE"/);
  assert.match(html, /id="taskCompleteEvidence"/);
  assert.match(app, /data-alert-task=/);
  assert.match(app, /action:'ALERT_TASK_CREATED'/);
  assert.match(app, /action:'TASK_COMPLETED'/);
  assert.match(app, /completionNotes:notes/);
  assert.match(css, /Build 68 — actionable farm operations/);
  assert.match(worker, /farm-manager-v74/);
});

test("decision dashboard compares poultry livestock finance and verified targets", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const css = await readFile(new URL("../public/admin.css", import.meta.url), "utf8");
  const worker = await readFile(new URL("../public/sw.js", import.meta.url), "utf8");
  assert.match(html, /id="analyticsLayRate"/);
  assert.match(html, /id="analyticsBreeding"/);
  assert.match(html, /id="weeklySummaryEvidence"/);
  assert.match(html, /id="targetWarningRows"/);
  assert.match(app, /layRate=layerBirds\?/);
  assert.match(app, /feedDays=recentFeed\?/);
  assert.match(app, /Evidence: \$\{sales\.length\} sales/);
  assert.match(css, /Build 69 — farm analytics and decision dashboard/);
  assert.match(worker, /farm-manager-v74/);
});

test("sales stabilization supports multi-item invoices credit control returns and safe voids", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  assert.match(html, /Create multi-item invoice/);
  assert.match(html, /Credit limit \(GHS\)/);
  assert.match(html, /Record return or refund/);
  assert.match(app, /function saleLines/);
  assert.match(app, /SalesReturn:'salesReturns'/);
  assert.match(app, /data-void-sale/);
  assert.match(html, /Optional · leave blank for no limit/);
  assert.doesNotMatch(html, /id="customerCreditLimit"[^>]*required/);
  assert.match(app, /creditLimit:creditValue===''.*?null:Number\(creditValue\)/);
  assert.match(app, /if\(hasLimit&&newCredit>limit/);
  assert.doesNotMatch(app, /customer has no credit limit/);
});

test("stabilization keeps reports tasks and assistant interactive", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  for (const id of ["reports", "tasks", "assistant", "assistantForm", "assistantSubmit", "assistantStatus"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /populationRows=reportRows\(state\.populationEvents,window\)/);
  assert.match(app, /populationRows\.filter\(row=>row\.flockId===flock\.id/);
  assert.doesNotMatch(app, /const window=.*?population=reportRows\(state\.populationEvents,window\)/);
  assert.match(app, /\(state\.offlineQueue\|\|\[\]\)\.filter\(r=>r\.status==='PENDING_SYNC'\)/);
  assert.match(app, /try\{renderView\(name\);\}catch\(error\)/);
  assert.match(app, /requestSubmit\(\)/);
  assert.match(app, /The assistant could not complete that answer/);
});

test("tasks delivery navigation and farm branding remain operational", async () => {
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const css = await readFile(new URL("../public/admin.css", import.meta.url), "utf8");
  const worker = await readFile(new URL("../public/sw.js", import.meta.url), "utf8");
  assert.match(app, /function taskLinkedOptions\(\).*?enabled=enabledFarmSystems\(\)/s);
  assert.doesNotMatch(app, /function taskLinkedOptions\(\).*?systemEnabled\(/s);
  assert.match(app, /function updateDeliveryFields\(\).*?orderFulfilment\.value==='DELIVERY'/s);
  assert.match(app, /\$\('#orderLocation'\)\.required=delivery/);
  assert.match(app, /viewBackBtn\.addEventListener\('click'/);
  assert.match(app, /id="setupFarmLogo"/);
  assert.match(app, /function renderFarmBrand/);
  assert.match(app, /farmLogoHtml\('mark'\)/);
  assert.match(app, /class="document-toolbar"/);
  assert.match(css, /reliable navigation, conditional delivery and farm branding/);
  assert.match(worker, /farm-manager-v74-stabilization-80/);
});

test("uploaded farm logos stay complete and mobile page titles remain readable", async () => {
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const css = await readFile(new URL("../public/admin.css", import.meta.url), "utf8");
  assert.match(css, /complete logo artwork and readable mobile header/);
  assert.match(css, /\.farm-brand-mark\.has-logo.*?background-size:contain/s);
  assert.match(css, /\.topbar-title\{display:grid;grid-template-columns:auto auto minmax\(0,1fr\)/);
  assert.match(css, /\.topbar-title h1.*?white-space:normal/s);
  assert.match(app, /\.mark\{object-fit:contain;background:#fff/);
  assert.match(app, /\.document-logo\{.*?object-fit:contain/s);
});

test("single-system farms hide incompatible records and controls", async () => {
  const app=await readFile(new URL('../public/app.js',import.meta.url),'utf8');
  assert.match(app, /switcher\.hidden=enabled\.size<2/);
  assert.match(app, /configureOptions\('#healthTargetType'/);
  assert.match(app, /configureOptions\('#planSystem'/);
  assert.match(app, /configureOptions\('#housingType'/);
  assert.match(app, /eggDays=enabled\.has\('FLOCKS'\)/);
  assert.match(app, /milkDays=enabled\.has\('LIVESTOCK'\)/);
  assert.match(app, /enabledSystems\.has\('FLOCKS'\)\?\(state\.flocks/);
  assert.doesNotMatch(app, /class="add-system-card"/);
});

test("quotation confirmation reserves a compatible live batch with visible failures", async () => {
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const css = await readFile(new URL("../public/admin.css", import.meta.url), "utf8");
  assert.match(app, /function reservableLotForOrder/);
  assert.match(app, /ORDER_RESERVATION_BATCH_CHANGED/);
  assert.match(app, /order\.reservedAt=new Date\(\)\.toISOString\(\)/);
  assert.match(app, /Reservation needs .*?compatible/s);
  assert.match(app, /event\.stopImmediatePropagation\(\)/);
  assert.match(css, /\.order-action-status\.error/);
});

test("farm logo persists through restart bootstrap and active-farm reconciliation", async () => {
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const route = await readFile(new URL("../app/api/[[...path]]/route.ts", import.meta.url), "utf8");
  assert.match(app, /transaction\.entityType==='FarmProfile'.*?upsertCloudRecord\('farms'/s);
  assert.match(app, /state\.farms=cloud\.farms\.map\(farm=>farm\.id===cloud\.farm\?\.id\?\{\.\.\.farm,\.\.\.cloud\.farm\}:farm\)/);
  assert.match(app, /key!=='farms'/);
  assert.match(route, /command\.entityType === "FarmProfile".*?state\.farms = \[\.\.\.farms\.filter/s);
});
