-- Stop application/maintenance writers. Use the controlled database owner.
-- Verify a schema-2 backup with the previous pinned tools before migration.
-- This adds evidence for FUTURE choices; it does not invent historical consent.
BEGIN;
SET LOCAL ROLE openid_owner;
SET LOCAL search_path=openid,pg_catalog;
LOCK TABLE schema_version IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF (SELECT array_agg(version) FROM schema_version) IS DISTINCT FROM ARRAY[2] THEN
  RAISE EXCEPTION 'schema version 2 required';
 END IF;
END $$;
CREATE TABLE enrollment_policies(digest text PRIMARY KEY CHECK(digest ~ '^[a-f0-9]{64}$'),
 record text NOT NULL CHECK(octet_length(record)<=65536));
CREATE TABLE enrollment_consents(id text PRIMARY KEY CHECK(id ~ '^[a-f0-9]{64}$'),
 subject text NOT NULL CHECK(subject ~ '^[a-f0-9]{64}$'), policy_digest text NOT NULL REFERENCES enrollment_policies,
 accepted bigint NOT NULL CHECK(accepted BETWEEN 0 AND 253402300799),
 proof text NOT NULL CHECK(octet_length(proof)<=16384),
 withdrawn bigint CHECK(withdrawn BETWEEN accepted AND 253402300799));
CREATE INDEX consent_subject ON enrollment_consents(subject,accepted);
CREATE TABLE credential_consents(credential text PRIMARY KEY REFERENCES credentials,
 receipt text UNIQUE NOT NULL REFERENCES enrollment_consents);
CREATE FUNCTION guard_consent() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,openid,pg_temp AS $$
BEGIN
 IF ROW(NEW.id,NEW.subject,NEW.policy_digest,NEW.accepted,NEW.proof)
      IS DISTINCT FROM ROW(OLD.id,OLD.subject,OLD.policy_digest,OLD.accepted,OLD.proof)
    OR NEW.withdrawn IS NULL OR (OLD.withdrawn IS NOT NULL AND NEW.withdrawn IS DISTINCT FROM OLD.withdrawn)
 THEN RAISE EXCEPTION 'consent evidence is immutable; withdrawal is permanent'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER consent_immutable BEFORE UPDATE ON enrollment_consents FOR EACH ROW EXECUTE FUNCTION guard_consent();
GRANT SELECT,INSERT ON enrollment_policies,enrollment_consents,credential_consents TO openid_enroller;
GRANT UPDATE(withdrawn) ON enrollment_consents TO openid_enroller;
GRANT SELECT ON enrollment_policies,enrollment_consents,credential_consents TO openid_backup;
REVOKE ALL ON FUNCTION guard_consent() FROM PUBLIC;
ALTER TABLE schema_version DROP CONSTRAINT schema_version_version_check;
UPDATE schema_version SET version=3;
ALTER TABLE schema_version ADD CONSTRAINT schema_version_version_check CHECK(version=3);
COMMIT;
