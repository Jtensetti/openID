-- Stop writers, verify the schema-6 backup with its pinned tools, then migrate.
BEGIN;
SET LOCAL ROLE openid_owner;
SET LOCAL search_path=openid,pg_catalog;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
LOCK TABLE schema_version IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF (SELECT array_agg(version) FROM schema_version) IS DISTINCT FROM ARRAY[6] THEN
  RAISE EXCEPTION 'schema version 6 required';
 END IF;
END $$;
LOCK TABLE credentials,enrollment_consents IN ACCESS EXCLUSIVE MODE;
CREATE TABLE erasure_runs (
 id text PRIMARY KEY CHECK(id ~ '^[a-f0-9]{64}$'), time bigint NOT NULL CHECK(time>=0),
 decision text NOT NULL CHECK(octet_length(decision)<=32768),
 plan_sha256 text NOT NULL CHECK(plan_sha256 ~ '^[a-f0-9]{64}$'),
 counts text NOT NULL CHECK(octet_length(counts)<=16384));
-- No credential FK: a recovery decision must also block a key absent from an old backup.
CREATE TABLE erasure_subjects (
 credential text PRIMARY KEY CHECK(credential ~ '^[a-f0-9]{64}$'),
 first_decision text NOT NULL REFERENCES erasure_runs);
GRANT SELECT ON erasure_subjects TO openid_enroller;

CREATE OR REPLACE FUNCTION guard_credential() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,openid,pg_temp AS $$
BEGIN
 IF NEW.state!='REVOKED' THEN
  IF EXISTS(SELECT 1 FROM openid.erasure_subjects WHERE credential=NEW.id) THEN
   RAISE EXCEPTION 'key retired by rights decision'; END IF;
 END IF;
 IF TG_OP='INSERT' THEN
  IF EXISTS(SELECT 1 FROM enrollment_quarantine WHERE until_epoch>extract(epoch FROM clock_timestamp())) THEN
   RAISE EXCEPTION 'enrollment paused after restore'; END IF;
  IF NEW.state!='PENDING_REVIEW' OR NEW.expires IS NOT NULL OR NEW.decision IS NOT NULL
   OR abs(NEW.created-extract(epoch FROM clock_timestamp()))>60 THEN
   RAISE EXCEPTION 'pending credential required';
  END IF;
 ELSIF current_user!='openid_owner' AND NEW.state!='REVOKED' THEN
  RAISE EXCEPTION 'activation requires approval';
 ELSIF OLD.state='REVOKED' AND NEW.state!='REVOKED' THEN
  RAISE EXCEPTION 'revocation is permanent';
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION guard_consent() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,openid,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF EXISTS(SELECT 1 FROM openid.erasure_subjects WHERE credential=NEW.subject) THEN
   RAISE EXCEPTION 'key retired by rights decision'; END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.id,NEW.subject,NEW.policy_digest,NEW.accepted,NEW.proof)
      IS DISTINCT FROM ROW(OLD.id,OLD.subject,OLD.policy_digest,OLD.accepted,OLD.proof)
    OR NEW.withdrawn IS NULL OR (OLD.withdrawn IS NOT NULL AND NEW.withdrawn IS DISTINCT FROM OLD.withdrawn)
 THEN RAISE EXCEPTION 'consent evidence is immutable; withdrawal is permanent'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER consent_immutable ON enrollment_consents;
CREATE TRIGGER consent_immutable BEFORE INSERT OR UPDATE ON enrollment_consents
 FOR EACH ROW EXECUTE FUNCTION guard_consent();
REVOKE ALL ON erasure_runs,erasure_subjects FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_credential(),guard_consent() FROM PUBLIC;
GRANT SELECT ON erasure_runs,erasure_subjects TO openid_backup;
ALTER TABLE schema_version DROP CONSTRAINT schema_version_version_check;
UPDATE schema_version SET version=7;
ALTER TABLE schema_version ADD CONSTRAINT schema_version_version_check CHECK(version=7);
COMMIT;
