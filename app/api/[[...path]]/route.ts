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
  visitorLogs?: DataRecord[];
  sanitationSchedules?: DataRecord[];
  complianceDocuments?: DataRecord[];
};

const securityHeaders = { "cache-control": "no-store", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "permissions-policy": "camera=(self), microphone=(), geolocation=()", "content-security-policy": "frame-ancestors 'none'; object-src 'none'; base-uri 'self'", "strict-transport-security": "max-age=31536000; includeSubDomains" };
const reply = (data: unknown, status = 200) => Response.json(data, { status, headers: securityHeaders });
const id = (prefix: string) => `${prefix}_${crypto.randomUUID()}`;
const now = () => new Date().toISOString();
const bytesToHex = (bytes: Uint8Array) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
async function database() {
  const { env } = await import("cloudflare:workers");
  if (!env.DB) throw new Error("ACCOUNT_STORAGE_UNAVAILABLE");
  return env.DB;
}
async function objectStore() {
  const { env } = await import("cloudflare:workers");
  if (!env.BUCKET) throw new Error("DOCUMENT_STORAGE_UNAVAILABLE");
  return env.BUCKET;
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
      db.prepare("CREATE TABLE IF NOT EXISTS user_security (user_id TEXT PRIMARY KEY NOT NULL, totp_secret_cipher TEXT, mfa_enabled INTEGER NOT NULL DEFAULT 0, recovery_hashes TEXT NOT NULL DEFAULT '[]', updated_at TEXT NOT NULL)"),
      db.prepare("CREATE TABLE IF NOT EXISTS mfa_challenges (challenge_hash TEXT PRIMARY KEY NOT NULL, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)"),
      db.prepare("CREATE TABLE IF NOT EXISTS auth_rate_limits (key_hash TEXT PRIMARY KEY NOT NULL, failures INTEGER NOT NULL DEFAULT 0, first_at INTEGER NOT NULL, locked_until INTEGER NOT NULL DEFAULT 0)"),
      db.prepare("CREATE TABLE IF NOT EXISTS security_events (id TEXT PRIMARY KEY NOT NULL, organization_id TEXT NOT NULL, user_id TEXT, event_type TEXT NOT NULL, ip_address TEXT, user_agent TEXT, details TEXT, created_at TEXT NOT NULL)"),
      db.prepare("CREATE INDEX IF NOT EXISTS security_events_org_idx ON security_events(organization_id, created_at)"),
      db.prepare("CREATE TABLE IF NOT EXISTS user_permissions (user_id TEXT PRIMARY KEY NOT NULL, permissions_json TEXT NOT NULL DEFAULT '[]', updated_by TEXT NOT NULL, updated_at TEXT NOT NULL)"),
      db.prepare("CREATE TABLE IF NOT EXISTS approval_requests (id TEXT PRIMARY KEY NOT NULL, organization_id TEXT NOT NULL, requested_by TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, command_json TEXT NOT NULL, reason TEXT NOT NULL, amount REAL NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'PENDING', reviewed_by TEXT, reviewed_at TEXT, created_at TEXT NOT NULL)"),
      db.prepare("CREATE INDEX IF NOT EXISTS approval_requests_org_idx ON approval_requests(organization_id, status, created_at)"),
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
    db.prepare("CREATE TABLE IF NOT EXISTS user_security (user_id TEXT PRIMARY KEY NOT NULL, totp_secret_cipher TEXT, mfa_enabled INTEGER NOT NULL DEFAULT 0, recovery_hashes TEXT NOT NULL DEFAULT '[]', updated_at TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS mfa_challenges (challenge_hash TEXT PRIMARY KEY NOT NULL, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS auth_rate_limits (key_hash TEXT PRIMARY KEY NOT NULL, failures INTEGER NOT NULL DEFAULT 0, first_at INTEGER NOT NULL, locked_until INTEGER NOT NULL DEFAULT 0)"),
    db.prepare("CREATE TABLE IF NOT EXISTS security_events (id TEXT PRIMARY KEY NOT NULL, organization_id TEXT NOT NULL, user_id TEXT, event_type TEXT NOT NULL, ip_address TEXT, user_agent TEXT, details TEXT, created_at TEXT NOT NULL)"),
    db.prepare("CREATE INDEX IF NOT EXISTS security_events_org_idx ON security_events(organization_id, created_at)"),
    db.prepare("CREATE TABLE IF NOT EXISTS user_permissions (user_id TEXT PRIMARY KEY NOT NULL, permissions_json TEXT NOT NULL DEFAULT '[]', updated_by TEXT NOT NULL, updated_at TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS approval_requests (id TEXT PRIMARY KEY NOT NULL, organization_id TEXT NOT NULL, requested_by TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, command_json TEXT NOT NULL, reason TEXT NOT NULL, amount REAL NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'PENDING', reviewed_by TEXT, reviewed_at TEXT, created_at TEXT NOT NULL)"),
    db.prepare("CREATE INDEX IF NOT EXISTS approval_requests_org_idx ON approval_requests(organization_id, status, created_at)"),
  ]);
  const sessionColumns=await db.prepare("PRAGMA table_info(sessions)").all<{name:string}>(),sessionNames=new Set(sessionColumns.results.map(column=>column.name)),sessionUpgrades=[];
  if(!sessionNames.has("device_id"))sessionUpgrades.push(db.prepare("ALTER TABLE sessions ADD COLUMN device_id TEXT"));
  if(!sessionNames.has("device_name"))sessionUpgrades.push(db.prepare("ALTER TABLE sessions ADD COLUMN device_name TEXT"));
  if(!sessionNames.has("last_seen_at"))sessionUpgrades.push(db.prepare("ALTER TABLE sessions ADD COLUMN last_seen_at TEXT"));
  if(sessionUpgrades.length)await db.batch(sessionUpgrades);
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

function strongPassword(password: string) { return password.length >= 12 && /[a-z]/.test(password) && /[A-Z]/.test(password) && /\d/.test(password); }
function requestMeta(request: Request) { return { ip: request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown", userAgent: (request.headers.get("user-agent") || "unknown").slice(0, 240) }; }
async function securityEvent(request: Request, eventType: string, user?: { id?: string; organizationId?: string }, details = "") {
  if (!user?.organizationId) return;
  try {
    const meta=requestMeta(request);
    await (await database()).prepare("INSERT INTO security_events (id,organization_id,user_id,event_type,ip_address,user_agent,details,created_at) VALUES (?,?,?,?,?,?,?,?)").bind(id("sec"),user.organizationId,user.id||null,eventType,meta.ip,meta.userAgent,details.slice(0,500),now()).run();
  } catch (error) {
    console.error("Security event could not be recorded", error);
  }
}
const base32Alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Encode(bytes: Uint8Array){let bits=0,value=0,result="";for(const byte of bytes){value=(value<<8)|byte;bits+=8;while(bits>=5){result+=base32Alphabet[(value>>>(bits-5))&31];bits-=5;}}if(bits>0)result+=base32Alphabet[(value<<(5-bits))&31];return result;}
function base32Decode(value: string){let bits=0,buffer=0,output:number[]=[];for(const char of value.replace(/=|\s/g,"").toUpperCase()){const index=base32Alphabet.indexOf(char);if(index<0)continue;buffer=(buffer<<5)|index;bits+=5;if(bits>=8){output.push((buffer>>>(bits-8))&255);bits-=8;}}return new Uint8Array(output);}
async function mfaKey(){const {env}=await import("cloudflare:workers");const secret=String((env as unknown as Record<string,unknown>).MFA_ENCRYPTION_KEY||"");if(secret.length<32)throw new Error("MFA_SECURITY_UNAVAILABLE");return crypto.subtle.importKey("raw",await crypto.subtle.digest("SHA-256",new TextEncoder().encode(secret)),{name:"AES-GCM"},false,["encrypt","decrypt"]);}
async function encryptMfaSecret(secret:string){const iv=crypto.getRandomValues(new Uint8Array(12)),data=new TextEncoder().encode(secret),encrypted=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},await mfaKey(),data));return `${btoa(String.fromCharCode(...iv))}.${btoa(String.fromCharCode(...encrypted))}`;}
async function decryptMfaSecret(cipher:string){const [iv64,data64]=cipher.split("."),iv=Uint8Array.from(atob(iv64),c=>c.charCodeAt(0)),data=Uint8Array.from(atob(data64),c=>c.charCodeAt(0)),plain=await crypto.subtle.decrypt({name:"AES-GCM",iv},await mfaKey(),data);return new TextDecoder().decode(plain);}
async function totp(secret:string,time=Date.now()){const counter=Math.floor(time/30000),bytes=new Uint8Array(8);let n=counter;for(let i=7;i>=0;i--){bytes[i]=n&255;n=Math.floor(n/256);}const key=await crypto.subtle.importKey("raw",base32Decode(secret),{name:"HMAC",hash:"SHA-1"},false,["sign"]),hash=new Uint8Array(await crypto.subtle.sign("HMAC",key,bytes)),offset=hash[hash.length-1]&15,code=((hash[offset]&127)<<24|(hash[offset+1]&255)<<16|(hash[offset+2]&255)<<8|(hash[offset+3]&255))%1000000;return String(code).padStart(6,"0");}
async function verifyTotp(secret:string,code:string){const clean=String(code||"").replace(/\s/g,"");for(const offset of [-30000,0,30000])if(await totp(secret,Date.now()+offset)===clean)return true;return false;}
function recoveryCodes(){return Array.from({length:8},()=>`${crypto.randomUUID().replaceAll("-","").slice(0,4)}-${crypto.randomUUID().replaceAll("-","").slice(0,4)}`.toUpperCase());}
async function rateLimitKey(identifier:string,request:Request){return sha256(`${identifier}|${requestMeta(request).ip}`);}
async function rateLimited(keyHash:string){const row=await (await database()).prepare("SELECT failures,locked_until AS lockedUntil FROM auth_rate_limits WHERE key_hash = ?").bind(keyHash).first<{failures:number;lockedUntil:number}>();return Boolean(row&&row.lockedUntil>Date.now());}
async function recordLoginFailure(keyHash:string){const db=await database(),row=await db.prepare("SELECT failures,first_at AS firstAt FROM auth_rate_limits WHERE key_hash = ?").bind(keyHash).first<{failures:number;firstAt:number}>(),fresh=!row||Date.now()-row.firstAt>15*60*1000,failures=fresh?1:row.failures+1,lockedUntil=failures>=5?Date.now()+15*60*1000:0;await db.prepare("INSERT INTO auth_rate_limits (key_hash,failures,first_at,locked_until) VALUES (?,?,?,?) ON CONFLICT(key_hash) DO UPDATE SET failures=excluded.failures,first_at=excluded.first_at,locked_until=excluded.locked_until").bind(keyHash,failures,fresh?Date.now():row!.firstAt,lockedUntil).run();}

async function sessionFrom(request: Request): Promise<Session | null> {
  const header = request.headers.get("authorization") || "";
  if (!header.startsWith("Bearer ")) return null;
  const tokenHash = await sha256(header.slice(7));
  const row = await (await database()).prepare(`
    SELECT u.id, u.name, u.email, u.phone, u.role, u.worker_id AS workerId, u.status, u.organization_id AS organizationId
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.expires_at > ? AND u.status = 'ACTIVE'
  `).bind(tokenHash, Date.now()).first<Session>();
  if(row){const deviceId=(request.headers.get("x-device-id")||"").slice(0,100),deviceName=(request.headers.get("x-device-name")||"Unknown device").slice(0,120);await (await database()).prepare("UPDATE sessions SET device_id=?,device_name=?,last_seen_at=? WHERE token_hash=?").bind(deviceId,deviceName,now(),tokenHash).run();}
  return row || null;
}

async function issueSession(userId: string) {
  const token = `${crypto.randomUUID()}${crypto.randomUUID()}`.replaceAll("-", "");
  await (await database()).prepare("INSERT INTO sessions (token_hash,user_id,expires_at,created_at) VALUES (?,?,?,?)")
    .bind(await sha256(token), userId, Date.now() + 1000 * 60 * 60 * 24 * 7, now()).run();
  return token;
}

async function stateFor(organizationId: string) {
  const row = await (await database()).prepare("SELECT state_json AS stateJson FROM farm_states WHERE organization_id = ?")
    .bind(organizationId).first<{ stateJson: string }>();
  return (row ? JSON.parse(row.stateJson) : {}) as FarmState;
}

const managementRoles = new Set(["OWNER", "MANAGER"]);
const financeTypes = new Set(["Expense", "ProductionPlan", "ProductionLot", "CustomerOrder", "OrderPayment", "Delivery", "Sale", "SalePayment", "SupplierPayment", "CashAdjustment", "Budget", "FinanceStatement", "BIInsightAction", "AIProposalDecision", "Customer", "Supplier", "Purchase", "PurchaseRequisition", "GoodsReceipt", "ProfitCostAllocation", "RevenueAllocation", "PayrollRecord"]);
const supervisorWriteTypes = new Set(["AttendanceRecord", "WorkRecord", "AlertAction", "Task", "DailyRecord", "ProductionRecord", "StockMovement", "HealthRecord", "HealthProgram", "BiosecurityCheck", "DiseaseOutbreak", "VisitorLog", "SanitationSchedule", "ComplianceDocument", "InventoryItem", "FeedingRecord", "AnimalActivity", "LocationEvent", "LocationTransfer"]);
const workerWriteTypes = new Set(["AttendanceRecord", "WorkRecord", "AlertAction", "DailyRecord"]);
const vetWriteTypes = new Set(["HealthRecord", "HealthProgram", "BiosecurityCheck", "DiseaseOutbreak", "ComplianceDocument", "InventoryItem", "StockMovement", "BreedingEvent", "AnimalActivity", "Animal", "Flock", "AlertAction"]);
const permissionGroups:Record<string,Set<string>>={OPERATIONS:new Set(["AttendanceRecord","WorkRecord","AlertAction","Task","DailyRecord","WorkSchedule"]),FLOCKS:new Set(["Flock","FlockPopulationEvent","FlockPopulationReversal","ProductionRecord","FeedingRecord"]),LIVESTOCK:new Set(["Animal","AnimalActivity","BreedingEvent"]),HEALTH:new Set(["HealthRecord","HealthProgram","BiosecurityCheck","DiseaseOutbreak","ComplianceDocument"]),INVENTORY:new Set(["InventoryItem","StockMovement","StockMovementReversal","GoodsReceipt"]),FINANCE:new Set([...financeTypes]),TEAM:new Set(["TeamMember","PayrollRecord"])};
function commandGroup(type:string){return Object.entries(permissionGroups).find(([,types])=>types.has(type))?.[0]||"OPERATIONS";}
async function customPermissionAllows(session:Session,command:SyncCommand){if(session.role==="OWNER")return true;const row=await (await database()).prepare("SELECT permissions_json AS permissions FROM user_permissions WHERE user_id=?").bind(session.id).first<{permissions:string}>();if(!row)return true;const allowed=JSON.parse(row.permissions||"[]") as string[];return allowed.includes(commandGroup(command.entityType||""));}
function sensitiveCommand(command:SyncCommand){const type=command.entityType||"",record=command.payload?.record||{},amount=Number(record.amount||record.total||record.netPay||0),movement=String(record.type||"").toUpperCase();if(type==="Expense"&&amount>=2000)return{reason:"High-value expense",amount};if(type==="PayrollRecord")return{reason:"Payroll posting",amount};if(type==="Sale"&&(record.reversalOf||movement.includes("VOID")||amount>=10000))return{reason:record.reversalOf||movement.includes("VOID")?"Sale reversal or void":"High-value sale",amount};if(["StockMovement","StockMovementReversal"].includes(type)&&(movement.includes("ADJUST")||movement.includes("REVERS")||Math.abs(Number(record.quantityDelta||0))>=500))return{reason:"Material stock adjustment",amount:Math.abs(Number(record.quantityDelta||0))};return null;}
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
    if (workspace) for (const key of ["locations","locationEvents","flocks","animals","animalEvents","breedingRecords","suppliers","purchases","purchaseRequisitions","goodsReceipts","productionPlans","customers","customerOrders","orderPayments","deliveries","productionLots","sales","salePayments","supplierPayments","cashAdjustments","budgets","financeStatements","insightActions","aiMessages","aiProposalDecisions","expenses","tasks","attendanceRecords","workSchedules","workRecords","payrollRecords","alertActions","populationEvents","inventoryItems","stockMovements","production","feedPlans","feedRecords","profitCostAllocations","revenueAllocations","healthRecords","healthPrograms","biosecurityChecks","outbreaks","visitorLogs","sanitationSchedules","complianceDocuments","dailyRecords"]) filtered[key] = structuredClone(workspace[key] || []);
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
    if (!strongPassword(input.password)) return reply({ error: "PASSWORD_NOT_STRONG_ENOUGH" }, 400);
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
      inventoryItems: [], stockMovements: [], production: [], feedPlans: [], feedRecords: [], profitCostAllocations: [], revenueAllocations: [], healthRecords: [], healthPrograms: [], biosecurityChecks: [], outbreaks: [], visitorLogs: [], sanitationSchedules: [], complianceDocuments: [], dailyRecords: [], audit: [], farmWorkspaces: {}, crossFarmTransfers: [], activeFarmId: farmId,
    };
    try {
      await db.batch([
        db.prepare("INSERT INTO organizations (id,name,created_at) VALUES (?,?,?)").bind(organizationId, input.organizationName.trim(), createdAt),
        db.prepare("INSERT INTO farms (id,organization_id,name,code,country,created_at) VALUES (?,?,?,?,?,?)").bind(farmId, organizationId, input.farmName.trim(), (input.farmCode || "MAIN").trim().toUpperCase(), (input.country || "Ghana").trim(), createdAt),
        db.prepare("INSERT INTO users (id,organization_id,name,email,password_hash,role,worker_id,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)").bind(userId, organizationId, input.name.trim(), email, securedPassword, "OWNER", userId, "ACTIVE", createdAt),
        db.prepare("INSERT INTO farm_states (organization_id,state_json,updated_at) VALUES (?,?,?)").bind(organizationId, JSON.stringify(initialState), createdAt),
        db.prepare("INSERT INTO sessions (token_hash,user_id,expires_at,created_at) VALUES (?,?,?,?)").bind(await sha256(token), userId, Date.now() + 1000 * 60 * 60 * 24 * 7, createdAt),
      ]);
    } catch (error) {
      const message = String(error).toLowerCase();
      console.error("registration transaction failed", { message, emailDomain: email.split("@")[1] || "invalid" });
      const duplicate = message.includes("unique") || message.includes("already exists") || message.includes("constraint failed: users.email");
      return reply({ error: duplicate ? "EMAIL_EXISTS" : "REGISTRATION_TEMPORARY_ERROR" }, duplicate ? 409 : 503);
    }
    await securityEvent(request,"OWNER_ACCOUNT_CREATED",{id:userId,organizationId});
    return reply({ token, user: { id: userId, name: input.name.trim(), email, role: "OWNER", workerId: userId, organizationId }, farmId }, 201);
  }

  if (route === "auth/activate-staff" && method === "POST") {
    try { await ensureCompatibleSchema(); } catch { return reply({ error: "ACCOUNT_STORAGE_UNAVAILABLE" }, 503); }
    const input = await request.json().catch(() => ({})) as Record<string, string>;
    if (!input.identifier || !input.code || !input.password) return reply({ error: "ACTIVATION_FIELDS_REQUIRED" }, 400);
    if (!strongPassword(input.password)) return reply({ error: "PASSWORD_NOT_STRONG_ENOUGH" }, 400);
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
    const token = await issueSession(userId);await securityEvent(request,"STAFF_ACCOUNT_ACTIVATED",{id:userId,organizationId:invitation.organizationId},invitation.role);
    return reply({ token, user: { id: userId, name: invitation.workerName, email, phone, role: invitation.role, workerId: invitation.workerId, organizationId: invitation.organizationId } }, 201);
  }

  if (route === "auth/login" && method === "POST") {
    try { await ensureCompatibleSchema(); } catch { return reply({ error: "ACCOUNT_STORAGE_UNAVAILABLE" }, 503); }
    const input = await request.json() as { email?: string; password?: string };
    if (!input.email || !input.password) return reply({ error: "EMAIL_AND_PASSWORD_REQUIRED" }, 400);
    const identifier = normalizedIdentifier(input.email),keyHash=await rateLimitKey(identifier.value,request);
    if(await rateLimited(keyHash))return reply({error:"TOO_MANY_LOGIN_ATTEMPTS",retryAfterSeconds:900},429);
    const user = await (await database()).prepare("SELECT u.id,u.name,u.email,u.phone,u.role,u.worker_id AS workerId,u.status,u.organization_id AS organizationId,u.password_hash AS passwordHash,COALESCE(s.mfa_enabled,0) AS mfaEnabled FROM users u LEFT JOIN user_security s ON s.user_id=u.id WHERE (u.email = ? OR u.phone = ?) AND u.status = 'ACTIVE'")
      .bind(identifier.value, identifier.value).first<Session & { passwordHash: string;mfaEnabled:number }>();
    if (!user || !await verifyPassword(input.password, user.passwordHash)){await recordLoginFailure(keyHash);if(user)await securityEvent(request,"LOGIN_FAILED",user,"Invalid password");return reply({ error: "INVALID_CREDENTIALS" }, 401);}
    await (await database()).prepare("DELETE FROM auth_rate_limits WHERE key_hash = ?").bind(keyHash).run();
    if(user.mfaEnabled){const challenge=`${crypto.randomUUID()}${crypto.randomUUID()}`.replaceAll("-","");await (await database()).prepare("INSERT INTO mfa_challenges (challenge_hash,user_id,expires_at,attempts,created_at) VALUES (?,?,?,?,?)").bind(await sha256(challenge),user.id,Date.now()+5*60*1000,0,now()).run();await securityEvent(request,"PASSWORD_VERIFIED_MFA_REQUIRED",user);return reply({mfaRequired:true,challengeToken:challenge,user:{name:user.name,role:user.role}});}
    await (await database()).prepare("UPDATE users SET last_login_at = ? WHERE id = ?").bind(now(), user.id).run();
    const token = await issueSession(user.id);await securityEvent(request,"LOGIN_SUCCEEDED",user,"Password only; MFA not enabled");
    return reply({ token, user: { id: user.id, name: user.name, email: user.email, phone: user.phone, role: user.role, workerId: user.workerId, organizationId: user.organizationId } });
  }

  if(route==="auth/mfa/verify"&&method==="POST"){
    try{await ensureCompatibleSchema();}catch{return reply({error:"ACCOUNT_STORAGE_UNAVAILABLE"},503);}const input=await request.json().catch(()=>({})) as {challengeToken?:string;code?:string};if(!input.challengeToken||!input.code)return reply({error:"MFA_FIELDS_REQUIRED"},400);const db=await database(),challengeHash=await sha256(input.challengeToken),challenge=await db.prepare("SELECT user_id AS userId,expires_at AS expiresAt,attempts FROM mfa_challenges WHERE challenge_hash = ?").bind(challengeHash).first<{userId:string;expiresAt:number;attempts:number}>();if(!challenge||challenge.expiresAt<Date.now()||challenge.attempts>=5)return reply({error:"MFA_CHALLENGE_EXPIRED"},401);const user=await db.prepare("SELECT u.id,u.name,u.email,u.phone,u.role,u.worker_id AS workerId,u.organization_id AS organizationId,s.totp_secret_cipher AS cipher,s.recovery_hashes AS recoveryHashes FROM users u JOIN user_security s ON s.user_id=u.id WHERE u.id=? AND u.status='ACTIVE' AND s.mfa_enabled=1").bind(challenge.userId).first<Session&{cipher:string;recoveryHashes:string}>();if(!user)return reply({error:"MFA_UNAVAILABLE"},401);let valid=false,recoveryUsed=false;try{valid=await verifyTotp(await decryptMfaSecret(user.cipher),input.code);}catch{return reply({error:"MFA_SECURITY_UNAVAILABLE"},503);}if(!valid){const hash=await sha256(input.code.trim().toUpperCase()),hashes=JSON.parse(user.recoveryHashes||"[]") as string[],index=hashes.indexOf(hash);if(index>=0){valid=true;recoveryUsed=true;hashes.splice(index,1);await db.prepare("UPDATE user_security SET recovery_hashes=?,updated_at=? WHERE user_id=?").bind(JSON.stringify(hashes),now(),user.id).run();}}if(!valid){await db.prepare("UPDATE mfa_challenges SET attempts=attempts+1 WHERE challenge_hash=?").bind(challengeHash).run();await securityEvent(request,"MFA_FAILED",user);return reply({error:"INVALID_MFA_CODE"},401);}await db.batch([db.prepare("DELETE FROM mfa_challenges WHERE challenge_hash=?").bind(challengeHash),db.prepare("UPDATE users SET last_login_at=? WHERE id=?").bind(now(),user.id)]);const token=await issueSession(user.id);await securityEvent(request,recoveryUsed?"RECOVERY_CODE_USED":"MFA_LOGIN_SUCCEEDED",user);return reply({token,user:{id:user.id,name:user.name,email:user.email,phone:user.phone,role:user.role,workerId:user.workerId,organizationId:user.organizationId},recoveryUsed});
  }

  try { await ensureCompatibleSchema(); } catch { return reply({ error: "ACCOUNT_STORAGE_UNAVAILABLE" }, 503); }
  const session = await sessionFrom(request);
  if (!session) return reply({ error: "UNAUTHORIZED" }, 401);

  if(route==="security/status"&&method==="GET"){
    const db=await database(),header=request.headers.get("authorization")||"",currentHash=header.startsWith("Bearer ")?await sha256(header.slice(7)):"",security=await db.prepare("SELECT COALESCE(mfa_enabled,0) AS mfaEnabled,updated_at AS updatedAt FROM user_security WHERE user_id=?").bind(session.id).first<{mfaEnabled:number;updatedAt:string}>(),sessions=await db.prepare("SELECT token_hash AS sessionId,device_id AS deviceId,device_name AS deviceName,last_seen_at AS lastSeenAt,expires_at AS expiresAt,created_at AS createdAt FROM sessions WHERE user_id=? AND expires_at>? ORDER BY COALESCE(last_seen_at,created_at) DESC").bind(session.id,Date.now()).all(),events=await db.prepare("SELECT id,event_type AS eventType,ip_address AS ipAddress,user_agent AS userAgent,details,created_at AS createdAt FROM security_events WHERE organization_id=? AND (user_id=? OR ? IN ('OWNER','MANAGER')) ORDER BY created_at DESC LIMIT 30").bind(session.organizationId,session.id,session.role).all();return reply({mfaEnabled:Boolean(security?.mfaEnabled),role:session.role,sessions:sessions.results.map((row:any)=>({...row,current:row.sessionId===currentHash,sessionId:String(row.sessionId).slice(0,24)})),events:events.results});
  }

  if(route==="security/control-center"&&method==="GET"){
    if(!canManageStaff(session))return reply({error:"FORBIDDEN"},403);const db=await database(),accounts=await db.prepare("SELECT u.id,u.name,u.role,u.status,COALESCE(s.mfa_enabled,0) AS mfaEnabled,COALESCE(p.permissions_json,'[]') AS permissions FROM users u LEFT JOIN user_security s ON s.user_id=u.id LEFT JOIN user_permissions p ON p.user_id=u.id WHERE u.organization_id=? ORDER BY u.role,u.name").bind(session.organizationId).all(),approvals=await db.prepare("SELECT a.id,a.requested_by AS requestedBy,u.name AS requestedByName,a.entity_type AS entityType,a.entity_id AS entityId,a.reason,a.amount,a.status,a.reviewed_by AS reviewedBy,a.reviewed_at AS reviewedAt,a.created_at AS createdAt FROM approval_requests a LEFT JOIN users u ON u.id=a.requested_by WHERE a.organization_id=? ORDER BY CASE a.status WHEN 'PENDING' THEN 0 ELSE 1 END,a.created_at DESC LIMIT 80").bind(session.organizationId).all();return reply({accounts:accounts.results.map((row:any)=>({...row,mfaEnabled:Boolean(row.mfaEnabled),permissions:JSON.parse(row.permissions||"[]")})),approvals:approvals.results,policy:{expenseThreshold:2000,saleThreshold:10000,stockThreshold:500,managerMfaRequired:true}});
  }

  if(route==="security/permissions"&&method==="POST"){
    if(session.role!=="OWNER")return reply({error:"OWNER_APPROVAL_REQUIRED"},403);const input=await request.json().catch(()=>({})) as {userId?:string;permissions?:string[]},allowedGroups=Object.keys(permissionGroups),permissions=(input.permissions||[]).filter(value=>allowedGroups.includes(value)),db=await database(),ownerMfa=await db.prepare("SELECT COALESCE(mfa_enabled,0) AS enabled FROM user_security WHERE user_id=?").bind(session.id).first<{enabled:number}>();if(!ownerMfa?.enabled)return reply({error:"MFA_REQUIRED_FOR_SECURITY_ADMIN"},403);const target=await db.prepare("SELECT id,role FROM users WHERE id=? AND organization_id=?").bind(input.userId,session.organizationId).first<{id:string;role:string}>();if(!target||target.role==="OWNER")return reply({error:"INVALID_PERMISSION_TARGET"},400);await db.prepare("INSERT INTO user_permissions (user_id,permissions_json,updated_by,updated_at) VALUES (?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET permissions_json=excluded.permissions_json,updated_by=excluded.updated_by,updated_at=excluded.updated_at").bind(target.id,JSON.stringify(permissions),session.id,now()).run();await securityEvent(request,"STAFF_PERMISSIONS_CHANGED",session,`${target.id}: ${permissions.join(", ")}`);return reply({ok:true,permissions});
  }

  if(route==="security/approvals/decision"&&method==="POST"){
    if(session.role!=="OWNER")return reply({error:"OWNER_APPROVAL_REQUIRED"},403);const input=await request.json().catch(()=>({})) as {approvalId?:string;decision?:string},decision=String(input.decision||"").toUpperCase();if(!input.approvalId||!["APPROVED","REJECTED"].includes(decision))return reply({error:"INVALID_APPROVAL_DECISION"},400);const db=await database(),ownerMfa=await db.prepare("SELECT COALESCE(mfa_enabled,0) AS enabled FROM user_security WHERE user_id=?").bind(session.id).first<{enabled:number}>();if(!ownerMfa?.enabled)return reply({error:"MFA_REQUIRED_FOR_SECURITY_ADMIN"},403);const row=await db.prepare("SELECT id,status,entity_type AS entityType,entity_id AS entityId FROM approval_requests WHERE id=? AND organization_id=?").bind(input.approvalId,session.organizationId).first<{id:string;status:string;entityType:string;entityId:string}>();if(!row||row.status!=="PENDING")return reply({error:"APPROVAL_NOT_PENDING"},409);const reviewedAt=now(),noticeId=id("approval_notice"),notice={id:row.id,status:decision,entityType:row.entityType,entityId:row.entityId,reviewedAt,reviewedBy:session.name};await db.batch([db.prepare("UPDATE approval_requests SET status=?,reviewed_by=?,reviewed_at=? WHERE id=?").bind(decision,session.id,reviewedAt,row.id),db.prepare("INSERT INTO sync_commands (id,organization_id,entity_type,entity_id,payload_json,created_at) VALUES (?,?,?,?,?,?)").bind(noticeId,session.organizationId,"ApprovalDecision",row.id,JSON.stringify({record:notice}),reviewedAt)]);await securityEvent(request,`SENSITIVE_ACTION_${decision}`,session,row.id);return reply({ok:true,status:decision});
  }

  if(route==="security/mfa/setup"&&method==="POST"){
    const input=await request.json().catch(()=>({})) as {password?:string},db=await database(),user=await db.prepare("SELECT password_hash AS passwordHash,email,organization_id AS organizationId FROM users WHERE id=?").bind(session.id).first<{passwordHash:string;email:string;organizationId:string}>();if(!input.password||!user||!await verifyPassword(input.password,user.passwordHash))return reply({error:"CURRENT_PASSWORD_INVALID"},401);const bytes=crypto.getRandomValues(new Uint8Array(20)),secret=base32Encode(bytes);let cipher:string;try{cipher=await encryptMfaSecret(secret);}catch{return reply({error:"MFA_SECURITY_UNAVAILABLE"},503);}await db.prepare("INSERT INTO user_security (user_id,totp_secret_cipher,mfa_enabled,recovery_hashes,updated_at) VALUES (?,?,0,'[]',?) ON CONFLICT(user_id) DO UPDATE SET totp_secret_cipher=excluded.totp_secret_cipher,mfa_enabled=0,recovery_hashes='[]',updated_at=excluded.updated_at").bind(session.id,cipher,now()).run();await securityEvent(request,"MFA_SETUP_STARTED",session);const issuer="Farm Manager",label=encodeURIComponent(`${issuer}:${user.email}`),uri=`otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;return reply({secret,uri});
  }

  if(route==="security/mfa/enable"&&method==="POST"){
    const input=await request.json().catch(()=>({})) as {code?:string},db=await database(),row=await db.prepare("SELECT totp_secret_cipher AS cipher FROM user_security WHERE user_id=? AND mfa_enabled=0").bind(session.id).first<{cipher:string}>();if(!row?.cipher||!input.code)return reply({error:"MFA_SETUP_REQUIRED"},400);let valid=false;try{valid=await verifyTotp(await decryptMfaSecret(row.cipher),input.code);}catch{return reply({error:"MFA_SECURITY_UNAVAILABLE"},503);}if(!valid)return reply({error:"INVALID_MFA_CODE"},400);const codes=recoveryCodes(),hashes=await Promise.all(codes.map(code=>sha256(code)));await db.prepare("UPDATE user_security SET mfa_enabled=1,recovery_hashes=?,updated_at=? WHERE user_id=?").bind(JSON.stringify(hashes),now(),session.id).run();await securityEvent(request,"MFA_ENABLED",session);return reply({ok:true,recoveryCodes:codes});
  }

  if(route==="security/mfa/disable"&&method==="POST"){
    const input=await request.json().catch(()=>({})) as {password?:string;code?:string},db=await database(),user=await db.prepare("SELECT password_hash AS passwordHash FROM users WHERE id=?").bind(session.id).first<{passwordHash:string}>(),row=await db.prepare("SELECT totp_secret_cipher AS cipher FROM user_security WHERE user_id=? AND mfa_enabled=1").bind(session.id).first<{cipher:string}>();if(!input.password||!user||!await verifyPassword(input.password,user.passwordHash))return reply({error:"CURRENT_PASSWORD_INVALID"},401);if(!row?.cipher||!input.code||!await verifyTotp(await decryptMfaSecret(row.cipher),input.code))return reply({error:"INVALID_MFA_CODE"},400);await db.batch([db.prepare("UPDATE user_security SET mfa_enabled=0,totp_secret_cipher=NULL,recovery_hashes='[]',updated_at=? WHERE user_id=?").bind(now(),session.id),db.prepare("DELETE FROM sessions WHERE user_id=? AND token_hash<>?").bind(session.id,await sha256((request.headers.get("authorization")||"").slice(7)))]);await securityEvent(request,"MFA_DISABLED",session);return reply({ok:true});
  }

  if(route==="security/password"&&method==="POST"){
    const input=await request.json().catch(()=>({})) as {currentPassword?:string;newPassword?:string;code?:string},db=await database(),user=await db.prepare("SELECT password_hash AS passwordHash FROM users WHERE id=?").bind(session.id).first<{passwordHash:string}>(),security=await db.prepare("SELECT mfa_enabled AS mfaEnabled,totp_secret_cipher AS cipher FROM user_security WHERE user_id=?").bind(session.id).first<{mfaEnabled:number;cipher:string}>();if(!input.currentPassword||!user||!await verifyPassword(input.currentPassword,user.passwordHash))return reply({error:"CURRENT_PASSWORD_INVALID"},401);if(!input.newPassword||!strongPassword(input.newPassword))return reply({error:"PASSWORD_NOT_STRONG_ENOUGH"},400);if(security?.mfaEnabled&&(!input.code||!await verifyTotp(await decryptMfaSecret(security.cipher),input.code)))return reply({error:"INVALID_MFA_CODE"},400);const currentHash=await sha256((request.headers.get("authorization")||"").slice(7));await db.batch([db.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(await passwordHash(input.newPassword),session.id),db.prepare("DELETE FROM sessions WHERE user_id=? AND token_hash<>?").bind(session.id,currentHash)]);await securityEvent(request,"PASSWORD_CHANGED",session);return reply({ok:true});
  }

  if(route==="security/sessions/revoke"&&method==="POST"){
    const input=await request.json().catch(()=>({})) as {sessionId?:string;allOthers?:boolean},db=await database(),currentHash=await sha256((request.headers.get("authorization")||"").slice(7));if(input.allOthers)await db.prepare("DELETE FROM sessions WHERE user_id=? AND token_hash<>?").bind(session.id,currentHash).run();else if(input.sessionId)await db.prepare("DELETE FROM sessions WHERE user_id=? AND substr(token_hash,1,24)=? AND token_hash<>?").bind(session.id,input.sessionId,currentHash).run();else return reply({error:"SESSION_TARGET_REQUIRED"},400);await securityEvent(request,"SESSIONS_REVOKED",session,input.allOthers?"All other sessions":"One session");return reply({ok:true});
  }

  if(route==="auth/logout"&&method==="POST"){
    const token=(request.headers.get("authorization")||"").slice(7);
    if(token)await (await database()).prepare("DELETE FROM sessions WHERE token_hash=? AND user_id=?").bind(await sha256(token),session.id).run();
    await securityEvent(request,"LOGOUT",session);
    return reply({ok:true});
  }

  if (route === "compliance/files" && method === "POST") {
    if (!managementRoles.has(session.role) && !["SUPERVISOR", "VET"].includes(session.role)) return reply({ error: "FORBIDDEN" }, 403);
    const form = await request.formData(), file = form.get("file");
    if (!(file instanceof File)) return reply({ error: "FILE_REQUIRED" }, 400);
    const allowed = new Set(["application/pdf", "image/jpeg", "image/png", "image/webp"]);
    if (!allowed.has(file.type)) return reply({ error: "FILE_TYPE_NOT_ALLOWED" }, 415);
    if (file.size > 10 * 1024 * 1024) return reply({ error: "FILE_TOO_LARGE", limitMb: 10 }, 413);
    const fileId = id("evidence"), safeName = file.name.replace(/[^a-zA-Z0-9._-]+/g, "-").slice(-100), key = `${session.organizationId}/compliance/${fileId}-${safeName}`;
    try { await (await objectStore()).put(key, file.stream(), { httpMetadata: { contentType: file.type }, customMetadata: { organizationId: session.organizationId, uploadedBy: session.id, originalName: file.name } }); }
    catch (error) { console.error("compliance upload failed", error); return reply({ error: "DOCUMENT_STORAGE_UNAVAILABLE" }, 503); }
    return reply({ file: { id: fileId, storageKey: key, name: file.name, contentType: file.type, size: file.size, uploadedAt: now(), uploadedBy: session.name } }, 201);
  }

  if (path[0] === "compliance" && path[1] === "files" && path[2] && method === "GET") {
    const farmState = await stateFor(session.organizationId), document = (farmState.complianceDocuments || []).find((row) => String(row.id) === path[2]);
    if (!document || !document.storageKey || !String(document.storageKey).startsWith(`${session.organizationId}/`)) return reply({ error: "FILE_NOT_FOUND" }, 404);
    const object = await (await objectStore()).get(String(document.storageKey));if (!object) return reply({ error: "FILE_NOT_FOUND" }, 404);
    return new Response(object.body, { headers: { "content-type": String(document.contentType || object.httpMetadata?.contentType || "application/octet-stream"), "content-disposition": `inline; filename="${String(document.fileName || "evidence").replaceAll('"','')}"`, "cache-control": "private, max-age=300", "x-content-type-options": "nosniff" } });
  }

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
      db.prepare("SELECT u.id,u.name,u.email,u.phone,u.role,u.status,u.worker_id AS workerId,u.last_login_at AS lastLoginAt,u.created_at AS createdAt,COALESCE(s.mfa_enabled,0) AS mfaEnabled FROM users u LEFT JOIN user_security s ON s.user_id=u.id WHERE u.organization_id = ? ORDER BY u.name").bind(session.organizationId).all(),
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
    for(const command of commands)if(!await customPermissionAllows(session,command))return reply({error:"CUSTOM_PERMISSION_DENIED",entityType:command.entityType},403);
    const accepted: Array<{ id: string }> = [], duplicates: Array<{ id: string }> = [], conflicts: unknown[] = [];
    const state = await stateFor(session.organizationId);
    for (const command of commands) {
      if (!command.id) continue;
      const exists = await (await database()).prepare("SELECT id FROM sync_commands WHERE id = ?").bind(command.id).first();
      if (exists) { duplicates.push({ id: command.id }); continue; }
      const sensitive=session.role!=="OWNER"?sensitiveCommand(command):null;
      if(sensitive){const db=await database(),mfa=await db.prepare("SELECT COALESCE(mfa_enabled,0) AS enabled FROM user_security WHERE user_id=?").bind(session.id).first<{enabled:number}>();if(session.role==="MANAGER"&&!mfa?.enabled){conflicts.push({id:command.id,code:"MFA_REQUIRED_FOR_SENSITIVE_ACTION",reason:sensitive.reason});continue;}const approved=await db.prepare("SELECT id FROM approval_requests WHERE organization_id=? AND entity_type=? AND entity_id=? AND status='APPROVED' ORDER BY reviewed_at DESC LIMIT 1").bind(session.organizationId,command.entityType||"Unknown",command.entityId||command.id).first<{id:string}>();if(!approved){let pending=await db.prepare("SELECT id FROM approval_requests WHERE organization_id=? AND entity_type=? AND entity_id=? AND status='PENDING' LIMIT 1").bind(session.organizationId,command.entityType||"Unknown",command.entityId||command.id).first<{id:string}>();if(!pending){pending={id:id("approval")};await db.prepare("INSERT INTO approval_requests (id,organization_id,requested_by,entity_type,entity_id,command_json,reason,amount,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)").bind(pending.id,session.organizationId,session.id,command.entityType||"Unknown",command.entityId||command.id,JSON.stringify(command),sensitive.reason,sensitive.amount,"PENDING",now()).run();await securityEvent(request,"SENSITIVE_ACTION_APPROVAL_REQUESTED",session,`${sensitive.reason}: ${command.entityId||command.id}`);}conflicts.push({id:command.id,code:"OWNER_APPROVAL_REQUIRED",approvalRequestId:pending.id,reason:sensitive.reason});continue;}}
      await (await database()).prepare("INSERT INTO sync_commands (id,organization_id,entity_type,entity_id,payload_json,created_at) VALUES (?,?,?,?,?,?)")
        .bind(command.id, session.organizationId, command.entityType || "Unknown", command.entityId || command.id, JSON.stringify(command.payload || {}), now()).run();
      const payload = command.payload || {};
      if (command.entityType === "FarmSystemPreference" && payload.record) state.operatingProfile = payload.record;
      if (command.entityType === "FarmProfile" && payload.record) {
        state.farm = { ...(state.farm || {}), ...payload.record };
        const farms = Array.isArray(state.farms) ? state.farms : [];
        state.farms = [...farms.filter((farm) => farm.id !== payload.record?.id), { ...(farms.find((farm) => farm.id === payload.record?.id) || {}), ...payload.record }];
      }
      if (command.entityType === "FarmWorkspace" && payload.record?.farmId) state.farmWorkspaces = { ...(state.farmWorkspaces || {}), [String(payload.record.farmId)]: payload.record };
      const recordKeys: Record<string, keyof FarmState> = {
        Flock: "flocks", FlockPopulationEvent: "populationEvents", FlockPopulationReversal: "populationEvents",
        Animal: "animals", AnimalActivity: "animalEvents", DailyRecord: "dailyRecords",
        ProductionRecord: "production", ProductionPlan: "productionPlans", ProductionLot: "productionLots", StockMovement: "stockMovements", StockMovementReversal: "stockMovements",
        Farm: "farms", FarmLocation: "locations", LocationEvent: "locationEvents", LocationTransfer: "locationEvents", SpeciesCatalog: "speciesCatalog", BreedingEvent: "breedingRecords",
        Supplier: "suppliers", Purchase: "purchases", PurchaseRequisition: "purchaseRequisitions", GoodsReceipt: "goodsReceipts", Customer: "customers", CustomerOrder: "customerOrders", OrderPayment: "orderPayments", Delivery: "deliveries", Sale: "sales", SalePayment: "salePayments", SupplierPayment: "supplierPayments", CashAdjustment: "cashAdjustments", Budget: "budgets", FinanceStatement: "financeStatements", BIInsightAction: "insightActions", AIProposalDecision: "aiProposalDecisions", Expense: "expenses",
        CrossFarmTransfer: "crossFarmTransfers", Task: "tasks", TeamMember: "team", AttendanceRecord: "attendanceRecords", WorkSchedule: "workSchedules", WorkRecord: "workRecords", PayrollRecord: "payrollRecords", AlertAction: "alertActions", InventoryItem: "inventoryItems", HealthRecord: "healthRecords", HealthProgram: "healthPrograms", BiosecurityCheck: "biosecurityChecks", DiseaseOutbreak: "outbreaks", VisitorLog: "visitorLogs", SanitationSchedule: "sanitationSchedules", ComplianceDocument: "complianceDocuments", FeedPlan: "feedPlans", FeedingRecord: "feedRecords", ProfitCostAllocation: "profitCostAllocations", RevenueAllocation: "revenueAllocations",
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
