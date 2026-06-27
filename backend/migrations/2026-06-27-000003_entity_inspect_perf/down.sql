DROP INDEX IF EXISTS idx_ss_actor_time;
DROP INDEX IF EXISTS idx_ct_actor_time;
ALTER TABLE actor_daily_counts DROP COLUMN IF EXISTS failed;
