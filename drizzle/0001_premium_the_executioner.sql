CREATE TABLE `staff_invitations` (
	`id` text PRIMARY KEY NOT NULL,
	`organization_id` text NOT NULL,
	`worker_id` text NOT NULL,
	`worker_name` text NOT NULL,
	`identifier` text NOT NULL,
	`identifier_type` text NOT NULL,
	`role` text NOT NULL,
	`code_hash` text NOT NULL,
	`created_by` text NOT NULL,
	`expires_at` integer NOT NULL,
	`status` text DEFAULT 'PENDING' NOT NULL,
	`created_at` text NOT NULL,
	`accepted_at` text
);
--> statement-breakpoint
ALTER TABLE `users` ADD `phone` text;--> statement-breakpoint
ALTER TABLE `users` ADD `worker_id` text;--> statement-breakpoint
ALTER TABLE `users` ADD `status` text DEFAULT 'ACTIVE' NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX `users_phone_unique` ON `users` (`phone`);