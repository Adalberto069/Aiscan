-- Synthetic local-only example; do not apply to a real database.
ALTER TABLE demo_private DISABLE ROW LEVEL SECURITY;
ALTER TABLE demo_protected ENABLE ROW LEVEL SECURITY;
