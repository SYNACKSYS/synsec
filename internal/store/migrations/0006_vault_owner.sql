-- A vault belongs to whoever created it.
--
-- Until now the interface sorted vaults by the role someone held on them, so a
-- vault handed over in "gestion" appeared among their own. That reads wrong:
-- people say "Alice's vault" regardless of what they are allowed to do in it,
-- and promoting someone should not make a vault change section under their
-- eyes.
--
-- Nullable on purpose. Deleting an account is already refused while it is the
-- sole manager of a vault, but an owner may legitimately hand management over
-- and then be removed - the vault survives, with nobody's name on it.
ALTER TABLE projects ADD COLUMN owner_id TEXT REFERENCES users (id) ON DELETE SET NULL;

-- Existing vaults have no owner recorded. The earliest manager is the closest
-- thing to the creator: vault_members is written with the creator first, both
-- from the interface and from the migration that introduced memberships.
UPDATE projects SET owner_id = (
    SELECT m.user_id
    FROM vault_members m
    WHERE m.project_id = projects.id AND m.role = 'manager'
    ORDER BY m.granted_at, m.user_id
    LIMIT 1
);

CREATE INDEX idx_projects_owner ON projects (owner_id);
