import bcrypt from "bcryptjs";

export const dynamic = "force-dynamic";

type Session = { id: string; name: string; email: string; phone?: string | null; role: string; workerId?: string | null; status?: string; organizationId: string };
type DataRecord = Record<string, unknown>;
type SyncOperation = { entity?: string; data: DataRecord };
type SyncCommand = {
  id: string;
  entityType?: string;
  entityId?: string;
  localCreatedAt?: string;
  payload?: { record?: DataRecord; operations?: SyncOperation[] };
};
type FarmState = DataRecord & {
  farmWorkspaces?: Record<string, DataRecord>;
  crossFarmTransfers?: DataRecord[];
  operatingProfile?: DataRecord | null;
  flocks?: DataRecord[];
  animals?: DataRecord[];
  animalEvents?: DataRecord[];
  dailyRecords?: DataRecord[];
  populationEvents?: DataRecord[];
  production?: DataRecord[];
  productionLots?: DataRecord[];
  sales?: DataRecord[];
  salePayments?: DataRecord[];
  supplierPayments?: DataRecord[];
  cashAdjustments?: DataRecord[];
  budgets?: DataRecord[];
  financeStatements?: DataRecord[];
  insightActions?: DataRecord[];
  aiProposalDecisions?: DataRecord[];
  purchaseRequisitions?: DataRecord[];
  goodsReceipts?: DataRecord[];
  productionPlans?: DataRecord[];
  customerOrders?: DataRecord[];
  orderPayments?: DataRecord[];
  deliveries?: DataRecord[];
  stockMovements?: DataRecord[];
  locations?: DataRecord[];
  locationEvents?: DataRecord[];
  feedPlans?: DataRecord[];
  feedRecords?: DataRecord[];
  profitCostAllocations?: DataRecord[];
  revenueAllocations?: DataRecord[];
  attendanceRecords?: DataRecord[];
  workSchedules?: DataRecord[];
  workRecords?: DataRecord[];
  payrollRecords?: DataRecord[];
  alertActions?: DataRecord[];
  healthRecords?: DataRecord[];
  healthPrograms?: DataRecord[];
  biosecurityChecks?: DataRecord[];
  outbreaks?: DataRecord[];
};

const reply = (data: unknown, status = 200) =>
  Response.json(data, { status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
const id = (prefix: string) => `${prefix}_${crypto.randomUUID()}`;
const now = () => new Date().toISOString();
const bytesToHex = (bytes: Uint8Array) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
async function database() {
  const { env } = await import("cloudflare:workers");
  if (!env.DB) throw new Error("ACCOUNT_STORAGE_UNAVAILABLE");
  return env.DB;
}
let schemaReady: Promise<void> | null = null;
async function ensureSchema() {
  if (!schemaReady) schemaReady = (async () => {
    const db = await database();
    await db.batch([
      db.prepare("CREATE TABLE IF NOT EXISTS organizations (id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL)"),
      db.prepare("CREATE TABLE IF NOT EXISTS farms (id TEXT PRIMARY KEY NOT NULL, organization_id TEXT NOT NULL, name TEXT NOT NULL, code TEXT NOT NULL, country TEXT NOT NULL DEFAULT 'Ghana', created_at TEXT NOT NULL)"),
      db.prepare("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY NOT NULL, organization_id TEXT NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'OWNER', phone TEXT, worker_id TEXT, status TEXT NOT NULL DEFAULT 'ACTIVE', created_at TEXT NOT NULL, last_login_at TEXT)"),
      db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users(email)"),
      db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS users_phone_unique ON users(phone)"),
      db.prepare("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY NOT NULL, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at TEXT NOT NULL)"),
      db.prepare("CREATE TABLE IF NOT EXISTS farm_states (organization_id TEXT PRIMARY KEY NOT NULL, state_json TEXT NOT NULL, updated_at TEXT NOT NULL)"),
      db.prepare("CREATE TABLE IF NOT EXISTS sync_commands (id TEXT PRIMARY KEY NOT NULL, organization_id TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, payload_json TEXT NOT NULL, created_at TEXT NOT NULL)"),
      db.prepare("CREATE TABLE IF NOT EXISTS staff_invitations (id TEXT PRIMARY KEY NOT NULL, organization_id TEXT NOT NULL, worker_id TEXT NOT NULL, worker_name TEXT NOT NULL, identifier TEXT NOT NULL, identifier_type TEXT NOT NULL, role TEXT NOT NULL, code_hash TEXT NOT NULL, created_by TEXT NOT NULL, expires_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING', created_at TEXT NOT NULL, accepted_at TEXT)"),
      db.prepare("CREATE INDEX IF NOT EXISTS staff_invitations_org_idx ON staff_invitations(organization_id, status)"),
    ]);
  })().catch((error) => { schemaReady = null; throw error; });
  return schemaReady;
}

async function ensureCompatibleSchema() {
  await ensureSchema();
  const db = await database();
  const columns = await db.prepare("PRAGMA table_info(users)").all<{ name: string }>();
  const names = new Set(columns.results.map((column) => column.name));
  const upgrades = [];
  if (!names.has("last_login_at")) upgrades.push(db.prepare("ALTER TABLE users ADD COLUMN last_login_at TEXT"));
  if (!names.has("phone")) upgrades.push(db.prepare("ALTER TABLE users ADD COLUMN phone TEXT"));
  if (!names.has("worker_id")) upgrades.push(db.prepare("ALTER TABLE users ADD COLUMN worker_id TEXT"));
  if (!names.has("status")) upgrades.push(db.prepare("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE'"));
  if (upgrades.length) await db.batch(upgrades);
  await db.batch([
    db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS users_phone_unique ON users(phone)"),
    db.prepare("CREATE TABLE IF NOT EXISTS staff_invitations (id TEXT PRIMARY KEY NOT NULL, organization_id TEXT NOT NULL, worker_id TEXT NOT NULL, worker_name TEXT NOT NULL, identifier TEXT NOT NULL, identifier_type TEXT NOT NULL, role TEXT NOT NULL, code_hash TEXT NOT NULL, created_by TEXT NOT NULL, expires_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING', created_at TEXT NOT NULL, accepted_at TEXT)"),
    db.prepare("CREATE INDEX IF NOT EXISTS staff_invitations_org_idx ON staff_invitations(organization_id, status)"),
  ]);
}

async function sha256(value: string) {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}

async function passwordHash(password: string) {
  return bcrypt.hash(password, 12);
}

async function verifyPassword(password: string, stored: string) {
  if (stored.startsWith("$2")) return bcrypt.compare(password, stored);
  const [, iterations, salt, expected] = stored.split("$");
  if (!iterations || !salt || !expected) return false;
  try {
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: new TextEncoder().encode(salt), iterations: Number(iterations) }, key, 256);
    return bytesToHex(new Uint8Array(bits)) === expected;
  } catch { return false; }
}

async function sessionFrom(request: Request): Promise<Session | null> {
  const header = request.headers.get("authorization") || "";
  if (!header.startsWith("Bearer ")) return null;
  const tokenHash = await sha256(header.slice(7));
  const row = await (await database()).prepare(`
    SELECT u.id, u.name, u.email, u.phone, u.role, u.worker_id AS workerId, u.status, u.organization_id AS organizationId
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.expires_at > ? AND u.status = 'ACTIVE'
  `).bind(tokenHash, Date.now()).first<Session>();
  return row || null;
}

async function issueSession(userId: string) {
  const token = `${crypto.randomUUID()}${crypto.randomUUID()}`.replaceAll("-", "");
  await (await database()).prepare("INSERT INTO sessions (token_hash,user_id,expires_at,created_at) VALUES (?,?,?,?)")
    .bind(await sha256(token), userId, Date.now() + 1000 * 60 * 60 * 24 * 30, now()).run();
  return token;
}

async function stateFor(organizationId: string) {
  const row = await (await database()).prepare("SELECT state_json AS stateJson FROM farm_states WHERE organization_id = ?")
    .bind(organizationId).first<{ stateJson: string }>();
  return (row ? JSON.parse(row.stateJson) : {}) as FarmState;
}

const managementRoles = new Set(["OWNER", "MANAGER"]);
const financeTypes = new Set(["Expense", "ProductionPlan", "ProductionLot", "CustomerOrder", "OrderPayment", "Delivery", "Sale", "SalePayment", "SupplierPayment", "CashAdjustment", "Budget", "FinanceStatement", "BIInsightAction", "AIProposalDecision", "Customer", "Supplier", "Purchase", "PurchaseRequisition", "GoodsReceipt", "ProfitCostAllocation", "RevenueAllocation", "PayrollRecord"]);
const supervisorWriteTypes = new Set(["AttendanceRecord", "WorkRecord", "AlertAction", "Task", "DailyRecord", "ProductionRecord", "StockMovement", "HealthRecord", "HealthProgram", "BiosecurityCheck", "DiseaseOutbreak", "InventoryItem", "FeedingRecord", "AnimalActivity", "LocationEvent", "LocationTransfer"]);
const workerWriteTypes = new Set(["AttendanceRecord", "WorkRecord", "AlertAction", "DailyRecord"]);
const vetWriteTypes = new Set(["HealthRecord", "HealthProgram", "BiosecurityCheck", "DiseaseOutbreak", "InventoryItem", "StockMovement", "BreedingEvent", "AnimalActivity", "Animal", "Flock", "AlertAction"]);
function normalizedIdentifier(value: unknown) {
  const raw = String(value || "").trim().toLowerCase();
  return raw.includes("@") ? { type: "EMAIL", value: raw } : { type: "PHONE", value: raw.replace(/[^+\d]/g, "") };
}
function canManageStaff(session: Session) { return managementRoles.has(session.role); }
function recordOwnedBy(session: Session, record?: DataRecord) {
  if (!session.workerId || !record) return false;
  return record.id === session.workerId || record.teamMemberId === session.workerId || record.assigneeId === session.workerId || record.workerId === session.workerId;
}
function canWriteCommand(session: Session, command: SyncCommand) {
  if (managementRoles.has(session.role)) return true;
  const type = command.entityType || "", record = command.payload?.record;
  if (session.role === "SUPERVISOR") return supervisorWriteTypes.has(type);
  if (session.role === "VET") return type === "AlertAction" ? recordOwnedBy(session, record) : vetWriteTypes.has(type) || (workerWriteTypes.has(type) && recordOwnedBy(session, record) && (type !== "WorkRecord" || record?.status === "SUBMITTED"));
  if (session.role === "WORKER") return workerWriteTypes.has(type) && (type === "DailyRecord" || (recordOwnedBy(session, record) && (type !== "WorkRecord" || record?.status === "SUBMITTED")));
  return false;
}
function canReadRecord(session: Session, type: string, record?: DataRecord) {
  if (managementRoles.has(session.role)) return true;
  if (financeTypes.has(type)) return type === "PayrollRecord" && recordOwnedBy(session, record);
  if (["TeamMember", "AttendanceRecord", "WorkSchedule", "WorkRecord", "AlertAction"].includes(type)) return session.role === "SUPERVISOR" || recordOwnedBy(session, record);
  return true;
}
function stateForRole(state: FarmState, session: Session) {
  if (session.role === "OWNER") return state;
  const filtered = structuredClone(state) as FarmState;
  const membership = (state.team as DataRecord[] || []).find((member) => member.id === session.workerId);
  const configuredFarmIds = Array.isArray(membership?.assignedFarmIds) ? membership.assignedFarmIds.map(String) : [];
  const fallbackFarmId = String(state.activeFarmId || (state.farm as DataRecord | undefined)?.id || (state.farms as DataRecord[] || [])[0]?.id || "");
  const allowedFarmIds = configuredFarmIds.length ? configuredFarmIds : fallbackFarmId ? [fallbackFarmId] : [];
  if (allowedFarmIds.length) {
    filtered.farms = (filtered.farms as DataRecord[] || []).filter((farm) => allowedFarmIds.includes(String(farm.id)));
    filtered.farmWorkspaces = Object.fromEntries(Object.entries(filtered.farmWorkspaces || {}).filter(([farmId]) => allowedFarmIds.includes(farmId)));
    if (!allowedFarmIds.includes(String(filtered.activeFarmId || ""))) filtered.activeFarmId = allowedFarmIds[0];
    filtered.farm = (filtered.farms as DataRecord[] || []).find((farm) => String(farm.id) === String(filtered.activeFarmId)) || (filtered.farms as DataRecord[] || [])[0] || filtered.farm;
    filtered.crossFarmTransfers = (filtered.crossFarmTransfers || []).filter((row) => allowedFarmIds.includes(String(row.fromFarmId)) || allowedFarmIds.includes(String(row.toFarmId)));
    const workspace = filtered.farmWorkspaces?.[String(filtered.activeFarmId)];
    if (workspace) for (const key of ["locations","locationEvents","flocks","animals","animalEvents","breedingRecords","suppliers","purchases","purchaseRequisitions","goodsReceipts","productionPlans","customers","customerOrders","orderPayments","deliveries","productionLots","sales","salePayments","supplierPayments","cashAdjustments","budgets","financeStatements","insightActions","aiMessages","aiProposalDecisions","expenses","tasks","attendanceRecords","workSchedules","workRecords","payrollRecords","alertActions","populationEvents","inventoryItems","stockMovements","production","feedPlans","feedRecords","profitCostAllocations","revenueAllocations","healthRecords","healthPrograms","biosecurityChecks","outbreaks","dailyRecords"]) filtered[key] = structuredClone(workspace[key] || []);
  }
  if (managementRoles.has(session.role)) return filtered;
  for (const key of ["expenses", "productionPlans", "productionLots", "customerOrders", "orderPayments", "deliveries", "sales", "salePayments", "supplierPayments", "cashAdjustments", "budgets", "financeStatements", "insightActions", "aiProposalDecisions", "customers", "suppliers", "purchases", "profitCostAllocations", "revenueAllocations"] as const) delete filtered[key];
  const own = (record: DataRecord) => recordOwnedBy(session, record);
  if (session.role === "SUPERVISOR") {
    filtered.team = (filtered.team as DataRecord[] || []).map(({ baseRate: _baseRate, payType: _payType, ...member }) => member);
    filtered.payrollRecords = (filtered.payrollRecords || []).filter(own);
  } else {
    filtered.team = (filtered.team as DataRecord[] || []).filter(own).map(({ baseRate: _baseRate, payType: _payType, ...member }) => member);
    filtered.attendanceRecords = (filtered.attendanceRecords || []).filter(own);
    filtered.workSchedules = (filtered.workSchedules || []).filter(own);
    filtered.workRecords = (filtered.workRecords || []).filter(own);
    filtered.alertActions = (filtered.alertActions || []).filter(own);
    filtered.payrollRecords = (filtered.payrollRecords || []).filter(own);
    filtered.tasks = (filtered.tasks as DataRecord[] || []).filter((task) => !task.assignee || String(task.assignee).toLowerCase() === session.name.toLowerCase());
    filtered.audit = [];
  }
  return filtered;
}

async function handle(request: Request, context: { params: Promise<{ path?: string[] }> }) {
  const { path = [] } = await context.params;
  const route = path.join("/");
  const method = request.method;

  if (route === "health" && method === "GET") return reply({ ok: true, service: "farm-manager", storage: "sites-d1", time: now() });

  if (route === "auth/register" && method === "POST") {
    try { await ensureCompatibleSchema(); } catch (error) { console.error("registration schema unavailable", error); return reply({ error: "ACCOUNT_STORAGE_UNAVAILABLE" }, 503); }
    const input = await request.json().catch(() => ({})) as Record<string, string>;
    const required = ["name", "email", "password", "organizationName", "farmName"];
    if (required.some((key) => !String(input[key] || "").trim())) return reply({ error: "REQUIRED_FIELDS_MISSING" }, 400);
    if (input.password.length < 8) return reply({ error: "PASSWORD_TOO_SHORT" }, 400);
    const email = input.email.trim().toLowerCase();
    const db = await database();
    if (await db.prepare("SELECT id FROM users WHERE email = ?").bind(email).first()) return reply({ error: "EMAIL_EXISTS" }, 409);

    const createdAt = now();
    const userId = id("usr"), organizationId = id("org"), farmId = id("farm");
    const token = `${crypto.randomUUID()}${crypto.randomUUID()}`.replaceAll("-", "");
    let securedPassword: string;
    try { securedPassword = await passwordHash(input.password); }
    catch (error) { console.error("registration password protection failed", error); return reply({ error: "PASSWORD_SECURITY_UNAVAILABLE" }, 503); }
    const initialState = {
      farms: [{ id: farmId, name: input.farmName.trim(), code: (input.farmCode || "MAIN").trim(), country: input.country || "Ghana" }],
      farm: { id: farmId, name: input.farmName.trim(), code: (input.farmCode || "MAIN").trim(), country: input.country || "Ghana", region: "" },
      locations: [], speciesCatalog: [
        { id: "species-chicken", name: "Chicken", breeds: ["Layer", "Broiler"] },
        { id: "species-goat", name: "Goat", breeds: [] }, { id: "species-cattle", name: "Cattle", breeds: [] },
        { id: "species-sheep", name: "Sheep", breeds: [] }, { id: "species-pig", name: "Pig", breeds: [] },
      ], operatingProfile: null, flocks: [], animals: [], animalEvents: [], locationEvents: [], breedingRecords: [], suppliers: [], purchases: [], customers: [], productionLots: [], sales: [], salePayments: [], supplierPayments: [], cashAdjustments: [], budgets: [], expenses: [], tasks: [],
      team: [{ id: userId, name: input.name.trim(), role: "OWNER", workRole: "Farm owner", phone: "", area: "All operations", status: "ACTIVE", createdAt }], attendanceRecords: [], workSchedules: [], workRecords: [], payrollRecords: [], alertActions: [], populationEvents: [],
      inventoryItems: [], stockMovements: [], production: [], feedPlans: [], feedRecords: [], profitCostAllocations: [], revenueAllocations: [], healthRecords: [], healthPrograms: [], biosecurityChecks: [], outbreaks: [], dailyRecords: [], audit: [], farmWorkspaces: {}, crossFarmTransfers: [], activeFarmId: farmId,
    };
    try {
      await db.batch([
        db.prepare("INSERT INTO organizations (id,name,created_at) VALUES (?,?,?)").bind(organizationId, input.organizationName.trim(), createdAt),
        db.prepare("INSERT INTO farms (id,organization_id,name,code,country,created_at) VALUES (?,?,?,?,?,?)").bind(farmId, organizationId, input.farmName.trim(), (input.farmCode || "MAIN").trim().toUpperCase(), (input.country || "Ghana").trim(), createdAt),
        db.prepare("INSERT INTO users (id,organization_id,name,email,password_hash,role,worker_id,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)").bind(userId, organizationId, input.name.trim(), email, securedPassword, "OWNER", userId, "ACTIVE", createdAt),
        db.prepare("INSERT INTO farm_states (organization_id,state_json,updated_at) VALUES (?,?,?)").bind(organizationId, JSON.stringify(initialState), createdAt),
        db.prepare("INSERT INTO sessions (token_hash,user_id,expires_at,created_at) VALUES (?,?,?,?)").bind(await sha256(token), userId, Date.now() + 1000 * 60 * 60 * 24 * 30, createdAt),
      ]);
    } catch (error) {
      const message = String(error).toLowerCase();
      console.error("registration transaction failed", { message, emailDomain: email.split("@")[1] || "invalid" });
      const duplicate = message.includes("unique") || message.includes("already exists") || message.includes("constraint failed: users.email");
      return reply({ error: duplicate ? "EMAIL_EXISTS" : "REGISTRATION_TEMPORARY_ERROR" }, duplicate ? 409 : 503);
    }
    return reply({ token, user: { id: userId, name: input.name.trim(), email, role: "OWNER", workerId: userId, organizationId }, farmId }, 201);
  }

  if (route === "auth/activate-staff" && method === "POST") {
    try { await ensureCompatibleSchema(); } catch { return reply({ error: "ACCOUNT_STORAGE_UNAVAILABLE" }, 503); }
    const input = await request.json().catch(() => ({})) as Record<string, string>;
    if (!input.identifier || !input.code || !input.password) return reply({ error: "ACTIVATION_FIELDS_REQUIRED" }, 400);
    if (input.password.length < 8) return reply({ error: "PASSWORD_TOO_SHORT" }, 400);
    const identifier = normalizedIdentifier(input.identifier);
    if ((identifier.type === "EMAIL" && !identifier.value.includes("@")) || (identifier.type === "PHONE" && identifier.value.replace(/\D/g, "").length < 7)) return reply({ error: "INVALID_IDENTIFIER" }, 400);
    const codeHash = await sha256(input.code.trim().toUpperCase());
    const db = await database();
    const invitation = await db.prepare(`SELECT id,organization_id AS organizationId,worker_id AS workerId,worker_name AS workerName,identifier,identifier_type AS identifierType,role,expires_at AS expiresAt FROM staff_invitations WHERE identifier = ? AND code_hash = ? AND status = 'PENDING' ORDER BY created_at DESC LIMIT 1`).bind(identifier.value, codeHash).first<{ id: string; organizationId: string; workerId: string; workerName: string; identifier: string; identifierType: string; role: string; expiresAt: number }>();
    if (!invitation || invitation.expiresAt < Date.now()) return reply({ error: "INVITATION_INVALID_OR_EXPIRED" }, 400);
    let securedPassword: string;
    try { securedPassword = await passwordHash(input.password); } catch { return reply({ error: "PASSWORD_SECURITY_UNAVAILABLE" }, 503); }
    const existing = await db.prepare("SELECT id FROM users WHERE organization_id = ? AND (email = ? OR phone = ?)").bind(invitation.organizationId, identifier.value, identifier.value).first<{ id: string }>();
    const userId = existing?.id || id("usr"), createdAt = now(), email = identifier.type === "EMAIL" ? identifier.value : `${identifier.value.replace(/\D/g, "")}.${invitation.organizationId}@staff.farm-manager.local`, phone = identifier.type === "PHONE" ? identifier.value : null;
    const farmState = await stateFor(invitation.organizationId), team = (farmState.team as DataRecord[] || []), member = team.find((row) => row.id === invitation.workerId);
    if (member) { member.role = invitation.role; member.accessStatus = "ACTIVE"; member.accessIdentifier = identifier.value; }
    try {
      if (existing) {
        await db.batch([
          db.prepare("UPDATE users SET name = ?, password_hash = ?, role = ?, phone = COALESCE(?,phone), worker_id = ?, status = 'ACTIVE' WHERE id = ?").bind(invitation.workerName, securedPassword, invitation.role, phone, invitation.workerId, userId),
          db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(userId),
          db.prepare("UPDATE staff_invitations SET status = 'ACCEPTED', accepted_at = ? WHERE id = ?").bind(createdAt, invitation.id),
          db.prepare("UPDATE farm_states SET state_json = ?, updated_at = ? WHERE organization_id = ?").bind(JSON.stringify(farmState), createdAt, invitation.organizationId),
        ]);
      } else {
        await db.batch([
          db.prepare("INSERT INTO users (id,organization_id,name,email,password_hash,role,phone,worker_id,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)").bind(userId, invitation.organizationId, invitation.workerName, email, securedPassword, invitation.role, phone, invitation.workerId, "ACTIVE", createdAt),
          db.prepare("UPDATE staff_invitations SET status = 'ACCEPTED', accepted_at = ? WHERE id = ?").bind(createdAt, invitation.id),
          db.prepare("UPDATE farm_states SET state_json = ?, updated_at = ? WHERE organization_id = ?").bind(JSON.stringify(farmState), createdAt, invitation.organizationId),
        ]);
      }
    } catch (error) {
      console.error("staff activation failed", error); return reply({ error: "STAFF_ACTIVATION_FAILED" }, 503);
    }
    const token = await issueSession(userId);
    return reply({ token, user: { id: userId, name: invitation.workerName, email, phone, role: invitation.role, workerId: invitation.workerId, organizationId: invitation.organizationId } }, 201);
  }

  if (route === "auth/login" && method === "POST") {
    try { await ensureCompatibleSchema(); } catch { return reply({ error: "ACCOUNT_STORAGE_UNAVAILABLE" }, 503); }
    const input = await request.json() as { email?: string; password?: string };
    if (!input.email || !input.password) return reply({ error: "EMAIL_AND_PASSWORD_REQUIRED" }, 400);
    const identifier = normalizedIdentifier(input.email);
    const user = await (await database()).prepare("SELECT id,name,email,phone,role,worker_id AS workerId,status,organization_id AS organizationId,password_hash AS passwordHash FROM users WHERE (email = ? OR phone = ?) AND status = 'ACTIVE'")
      .bind(identifier.value, identifier.value).first<Session & { passwordHash: string }>();
    if (!user || !await verifyPassword(input.password, user.passwordHash)) return reply({ error: "INVALID_CREDENTIALS" }, 401);
    await (await database()).prepare("UPDATE users SET last_login_at = ? WHERE id = ?").bind(now(), user.id).run();
    const token = await issueSession(user.id);
    return reply({ token, user: { id: user.id, name: user.name, email: user.email, phone: user.phone, role: user.role, workerId: user.workerId, organizationId: user.organizationId } });
  }

  try { await ensureCompatibleSchema(); } catch { return reply({ error: "ACCOUNT_STORAGE_UNAVAILABLE" }, 503); }
  const session = await sessionFrom(request);
  if (!session) return reply({ error: "UNAUTHORIZED" }, 401);

  if (route === "me" && method === "GET") return reply({ user: session });
  if (route === "farms" && method === "GET") {
    const result = await (await database()).prepare("SELECT id,name,code,country FROM farms WHERE organization_id = ? ORDER BY created_at")
      .bind(session.organizationId).all();
    return reply({ farms: result.results });
  }
  if (route === "bootstrap" && method === "GET") return reply({ ...stateForRole(await stateFor(session.organizationId), session), cloudMeta: { serverTime: now(), role: session.role } });

  if (route === "staff/access" && method === "GET") {
    if (!canManageStaff(session)) return reply({ error: "FORBIDDEN" }, 403);
    const db = await database();
    const [accounts, invitations] = await Promise.all([
      db.prepare("SELECT id,name,email,phone,role,status,worker_id AS workerId,last_login_at AS lastLoginAt,created_at AS createdAt FROM users WHERE organization_id = ? ORDER BY name").bind(session.organizationId).all(),
      db.prepare("SELECT id,worker_id AS workerId,worker_name AS workerName,identifier,identifier_type AS identifierType,role,expires_at AS expiresAt,status,created_at AS createdAt FROM staff_invitations WHERE organization_id = ? ORDER BY created_at DESC LIMIT 50").bind(session.organizationId).all(),
    ]);
    return reply({ accounts: accounts.results, invitations: invitations.results });
  }

  if (route === "staff/invitations" && method === "POST") {
    if (!canManageStaff(session)) return reply({ error: "FORBIDDEN" }, 403);
    const input = await request.json().catch(() => ({})) as Record<string, string>, allowedRoles = new Set(["MANAGER", "SUPERVISOR", "WORKER", "VET", "VIEWER"]), role = String(input.role || "WORKER").toUpperCase();
    if (!input.workerId || !input.identifier || !allowedRoles.has(role)) return reply({ error: "INVITATION_FIELDS_REQUIRED" }, 400);
    if (session.role !== "OWNER" && role === "MANAGER") return reply({ error: "OWNER_APPROVAL_REQUIRED" }, 403);
    const identifier = normalizedIdentifier(input.identifier);
    if ((identifier.type === "EMAIL" && !identifier.value.includes("@")) || (identifier.type === "PHONE" && identifier.value.replace(/\D/g, "").length < 7)) return reply({ error: "INVALID_IDENTIFIER" }, 400);
    const farmState = await stateFor(session.organizationId), team = (farmState.team as DataRecord[] || []), worker = team.find((row) => row.id === input.workerId);
    if (!worker) return reply({ error: "WORKER_PROFILE_NOT_FOUND" }, 404);
    const db = await database(), existing = await db.prepare("SELECT id,organization_id AS organizationId FROM users WHERE email = ? OR phone = ?").bind(identifier.value, identifier.value).first<{ id: string; organizationId: string }>();
    if (existing && existing.organizationId !== session.organizationId) return reply({ error: "IDENTIFIER_ALREADY_USED" }, 409);
    const inviteId = id("invite"), activationCode = `FM-${crypto.randomUUID().replaceAll("-", "").slice(0, 8).toUpperCase()}`, createdAt = now(), expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
    await db.batch([
      db.prepare("UPDATE staff_invitations SET status = 'REPLACED' WHERE organization_id = ? AND worker_id = ? AND status = 'PENDING'").bind(session.organizationId, input.workerId),
      db.prepare("INSERT INTO staff_invitations (id,organization_id,worker_id,worker_name,identifier,identifier_type,role,code_hash,created_by,expires_at,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)").bind(inviteId, session.organizationId, input.workerId, String(worker.name), identifier.value, identifier.type, role, await sha256(activationCode), session.id, expiresAt, "PENDING", createdAt),
    ]);
    worker.role = role; worker.accessStatus = "INVITED"; worker.accessIdentifier = identifier.value;
    farmState.audit = [...(farmState.audit as DataRecord[] || []), { id: id("audit"), action: "STAFF_INVITATION_CREATED", entityId: input.workerId, at: createdAt, createdBy: session.name }];
    await db.prepare("UPDATE farm_states SET state_json = ?, updated_at = ? WHERE organization_id = ?").bind(JSON.stringify(farmState), createdAt, session.organizationId).run();
    return reply({ invitation: { id: inviteId, workerId: input.workerId, workerName: worker.name, identifier: identifier.value, identifierType: identifier.type, role, activationCode, expiresAt, status: "PENDING", createdAt } }, 201);
  }

  if (route === "staff/accounts/status" && method === "POST") {
    if (!canManageStaff(session)) return reply({ error: "FORBIDDEN" }, 403);
    const input = await request.json().catch(() => ({})) as { userId?: string; status?: string }, status = String(input.status || "").toUpperCase();
    if (!input.userId || !["ACTIVE", "SUSPENDED"].includes(status)) return reply({ error: "INVALID_ACCOUNT_STATUS" }, 400);
    if (input.userId === session.id) return reply({ error: "CANNOT_SUSPEND_CURRENT_ACCOUNT" }, 400);
    const db = await database(), target = await db.prepare("SELECT id,role,worker_id AS workerId FROM users WHERE id = ? AND organization_id = ?").bind(input.userId, session.organizationId).first<{ id: string; role: string; workerId: string }>();
    if (!target) return reply({ error: "ACCOUNT_NOT_FOUND" }, 404);
    if (target.role === "OWNER" || (session.role !== "OWNER" && target.role === "MANAGER")) return reply({ error: "OWNER_APPROVAL_REQUIRED" }, 403);
    const updates = [db.prepare("UPDATE users SET status = ? WHERE id = ?").bind(status, target.id)];if (status === "SUSPENDED") updates.push(db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(target.id));await db.batch(updates);
    const farmState = await stateFor(session.organizationId), member = (farmState.team as DataRecord[] || []).find((row) => row.id === target.workerId);if (member) member.accessStatus = status;
    farmState.audit = [...(farmState.audit as DataRecord[] || []), { id: id("audit"), action: `STAFF_ACCOUNT_${status}`, entityId: target.id, at: now(), createdBy: session.name }];
    await db.prepare("UPDATE farm_states SET state_json = ?, updated_at = ? WHERE organization_id = ?").bind(JSON.stringify(farmState), now(), session.organizationId).run();
    return reply({ ok: true, status });
  }

  if (route === "sync/push" && method === "POST") {
    const input = await request.json() as { commands?: SyncCommand[] };
    const commands = Array.isArray(input.commands) ? input.commands : [];
    if (commands.length > 500) return reply({ error: "TOO_MANY_COMMANDS", limit: 500 }, 400);
    if (commands.some((command) => !canWriteCommand(session, command))) return reply({ error: "ROLE_PERMISSION_DENIED" }, 403);
    const accepted: Array<{ id: string }> = [], duplicates: Array<{ id: string }> = [], conflicts: unknown[] = [];
    const state = await stateFor(session.organizationId);
    for (const command of commands) {
      if (!command.id) continue;
      const exists = await (await database()).prepare("SELECT id FROM sync_commands WHERE id = ?").bind(command.id).first();
      if (exists) { duplicates.push({ id: command.id }); continue; }
      await (await database()).prepare("INSERT INTO sync_commands (id,organization_id,entity_type,entity_id,payload_json,created_at) VALUES (?,?,?,?,?,?)")
        .bind(command.id, session.organizationId, command.entityType || "Unknown", command.entityId || command.id, JSON.stringify(command.payload || {}), now()).run();
      const payload = command.payload || {};
      if (command.entityType === "FarmSystemPreference" && payload.record) state.operatingProfile = payload.record;
      if (command.entityType === "FarmProfile" && payload.record) state.farm = payload.record;
      if (command.entityType === "FarmWorkspace" && payload.record?.farmId) state.farmWorkspaces = { ...(state.farmWorkspaces || {}), [String(payload.record.farmId)]: payload.record };
      const recordKeys: Record<string, keyof FarmState> = {
        Flock: "flocks", FlockPopulationEvent: "populationEvents", FlockPopulationReversal: "populationEvents",
        Animal: "animals", AnimalActivity: "animalEvents", DailyRecord: "dailyRecords",
        ProductionRecord: "production", ProductionPlan: "productionPlans", ProductionLot: "productionLots", StockMovement: "stockMovements", StockMovementReversal: "stockMovements",
        Farm: "farms", FarmLocation: "locations", LocationEvent: "locationEvents", LocationTransfer: "locationEvents", SpeciesCatalog: "speciesCatalog", BreedingEvent: "breedingRecords",
        Supplier: "suppliers", Purchase: "purchases", PurchaseRequisition: "purchaseRequisitions", GoodsReceipt: "goodsReceipts", Customer: "customers", CustomerOrder: "customerOrders", OrderPayment: "orderPayments", Delivery: "deliveries", Sale: "sales", SalePayment: "salePayments", SupplierPayment: "supplierPayments", CashAdjustment: "cashAdjustments", Budget: "budgets", FinanceStatement: "financeStatements", BIInsightAction: "insightActions", AIProposalDecision: "aiProposalDecisions", Expense: "expenses",
        CrossFarmTransfer: "crossFarmTransfers", Task: "tasks", TeamMember: "team", AttendanceRecord: "attendanceRecords", WorkSchedule: "workSchedules", WorkRecord: "workRecords", PayrollRecord: "payrollRecords", AlertAction: "alertActions", InventoryItem: "inventoryItems", HealthRecord: "healthRecords", HealthProgram: "healthPrograms", BiosecurityCheck: "biosecurityChecks", DiseaseOutbreak: "outbreaks", FeedPlan: "feedPlans", FeedingRecord: "feedRecords", ProfitCostAllocation: "profitCostAllocations", RevenueAllocation: "revenueAllocations",
      };
      const recordKey = recordKeys[command.entityType || ""];
      if (payload.record && recordKey) {
        const records = Array.isArray(state[recordKey]) ? state[recordKey] as DataRecord[] : [];
        state[recordKey] = [...records.filter((record) => record.id !== payload.record?.id), payload.record];
      }
      if (command.entityType === "Farm" && payload.record?.id) await (await database()).prepare("INSERT OR REPLACE INTO farms (id,organization_id,name,code,country,created_at) VALUES (?,?,?,?,?,?)").bind(String(payload.record.id), session.organizationId, String(payload.record.name || "Farm"), String(payload.record.code || "FARM"), String(payload.record.country || "Ghana"), String(payload.record.createdAt || now())).run();
      for (const operation of payload.operations || []) {
        const key = operation.entity === "FlockPopulationEvent" ? "populationEvents" : operation.entity === "ProductionRecord" ? "production" : operation.entity === "StockMovement" ? "stockMovements" : null;
        if (key) state[key] = [...(state[key] || []).filter((record) => record.id !== operation.data.id), operation.data];
      }
      accepted.push({ id: command.id });
    }
    await (await database()).prepare("UPDATE farm_states SET state_json = ?, updated_at = ? WHERE organization_id = ?")
      .bind(JSON.stringify(state), now(), session.organizationId).run();
    return reply({ accepted, duplicates, conflicts });
  }

  if (route === "sync/pull" && method === "GET") {
    const since = new URL(request.url).searchParams.get("since") || "1970-01-01T00:00:00.000Z";
    const result = await (await database()).prepare("SELECT id,entity_type AS entityType,entity_id AS entityId,payload_json AS payloadJson,created_at AS createdAt FROM sync_commands WHERE organization_id = ? AND created_at > ? ORDER BY created_at")
      .bind(session.organizationId, since).all<{ id: string; entityType: string; entityId: string; payloadJson: string; createdAt: string }>();
    const farmState = await stateFor(session.organizationId), member = (farmState.team as DataRecord[] || []).find((row) => row.id === session.workerId), configuredFarmIds = Array.isArray(member?.assignedFarmIds) ? member.assignedFarmIds.map(String) : [], fallbackFarmId = String(farmState.activeFarmId || (farmState.farm as DataRecord | undefined)?.id || (farmState.farms as DataRecord[] || [])[0]?.id || ""), allowedFarmIds = session.role === "OWNER" ? null : new Set(configuredFarmIds.length ? configuredFarmIds : fallbackFarmId ? [fallbackFarmId] : []);
    const farmVisible = (record?: DataRecord) => !allowedFarmIds || !record || (record.farmId ? allowedFarmIds.has(String(record.farmId)) : record.fromFarmId || record.toFarmId ? allowedFarmIds.has(String(record.fromFarmId)) || allowedFarmIds.has(String(record.toFarmId)) : true);
    const transactions = result.results.map((row) => ({ ...row, payload: JSON.parse(row.payloadJson) as SyncCommand["payload"], payloadJson: undefined })).filter((row) => canReadRecord(session, row.entityType, row.payload?.record) && farmVisible(row.payload?.record));
    return reply({ transactions, serverTime: now() });
  }

  return reply({ error: "NOT_FOUND" }, 404);
}

export const GET = handle;
export const POST = handle;
