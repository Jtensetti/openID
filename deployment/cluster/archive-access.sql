-- Optional, repeatable column grants to the existing read-only audit role.
-- Apply as controlled database owner, including in a newly restored database.
BEGIN;
SET LOCAL ROLE openid_owner;
GRANT SELECT ON schema_version TO openid_auditor;
GRANT SELECT(id,public_key,state,created,expires,decision) ON credentials TO openid_auditor;
GRANT SELECT(credential,version,verified,document_expires) ON profiles TO openid_auditor;
GRANT SELECT(id,credential,kind,time,request) ON events TO openid_auditor;
GRANT SELECT ON enrollment_policies,enrollment_consents,credential_consents TO openid_auditor;
GRANT SELECT ON consent_retention_runs TO openid_auditor;
COMMIT;
