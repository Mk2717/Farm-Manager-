import { integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

export const organizations = sqliteTable("organizations", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  createdAt: text("created_at").notNull(),
});

export const farms = sqliteTable("farms", {
  id: text("id").primaryKey(),
  organizationId: text("organization_id").notNull(),
  name: text("name").notNull(),
  code: text("code").notNull(),
  country: text("country").notNull().default("Ghana"),
  createdAt: text("created_at").notNull(),
});

export const users = sqliteTable("users", {
  id: text("id").primaryKey(),
  organizationId: text("organization_id").notNull(),
  name: text("name").notNull(),
  email: text("email").notNull(),
  passwordHash: text("password_hash").notNull(),
  role: text("role").notNull().default("OWNER"),
  phone: text("phone"),
  workerId: text("worker_id"),
  status: text("status").notNull().default("ACTIVE"),
  createdAt: text("created_at").notNull(),
  lastLoginAt: text("last_login_at"),
}, (table) => ({ emailIdx: uniqueIndex("users_email_unique").on(table.email), phoneIdx: uniqueIndex("users_phone_unique").on(table.phone) }));

export const staffInvitations = sqliteTable("staff_invitations", {
  id: text("id").primaryKey(),
  organizationId: text("organization_id").notNull(),
  workerId: text("worker_id").notNull(),
  workerName: text("worker_name").notNull(),
  identifier: text("identifier").notNull(),
  identifierType: text("identifier_type").notNull(),
  role: text("role").notNull(),
  codeHash: text("code_hash").notNull(),
  createdBy: text("created_by").notNull(),
  expiresAt: integer("expires_at").notNull(),
  status: text("status").notNull().default("PENDING"),
  createdAt: text("created_at").notNull(),
  acceptedAt: text("accepted_at"),
});

export const sessions = sqliteTable("sessions", {
  tokenHash: text("token_hash").primaryKey(),
  userId: text("user_id").notNull(),
  expiresAt: integer("expires_at").notNull(),
  createdAt: text("created_at").notNull(),
});

export const farmStates = sqliteTable("farm_states", {
  organizationId: text("organization_id").primaryKey(),
  stateJson: text("state_json").notNull(),
  updatedAt: text("updated_at").notNull(),
});

export const syncCommands = sqliteTable("sync_commands", {
  id: text("id").primaryKey(),
  organizationId: text("organization_id").notNull(),
  entityType: text("entity_type").notNull(),
  entityId: text("entity_id").notNull(),
  payloadJson: text("payload_json").notNull(),
  createdAt: text("created_at").notNull(),
});
