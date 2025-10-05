-- Add Google OAuth fields to users table
ALTER TABLE users
ADD COLUMN google_id VARCHAR(255) UNIQUE,
ADD COLUMN is_verified BOOLEAN DEFAULT FALSE; 