-- Stop writers and verify a schema-5 backup with its pinned tools first.
-- Existing profiles can supply a link. Already lost links are not inferred.
BEGIN;
SET LOCAL ROLE openid_owner;
SET LOCAL search_path=openid,pg_catalog;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
LOCK TABLE schema_version IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF (SELECT array_agg(version) FROM schema_version) IS DISTINCT FROM ARRAY[5] THEN
  RAISE EXCEPTION 'schema version 5 required';
 END IF;
END $$;
LOCK TABLE credentials,persons,profiles IN ACCESS EXCLUSIVE MODE;
CREATE TABLE credential_persons (
 credential text PRIMARY KEY REFERENCES credentials, person text NOT NULL REFERENCES persons,
 UNIQUE(credential,person));
CREATE INDEX credential_person ON credential_persons(person);
INSERT INTO credential_persons SELECT credential,person FROM profiles;
ALTER TABLE profiles ADD CONSTRAINT profile_person_binding
 FOREIGN KEY(credential,person) REFERENCES credential_persons(credential,person);
CREATE FUNCTION record_profile_person() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
BEGIN
 IF TG_OP='UPDATE' AND ROW(NEW.credential,NEW.person) IS DISTINCT FROM ROW(OLD.credential,OLD.person) THEN
  RAISE EXCEPTION 'registration person binding is immutable';
 END IF;
 INSERT INTO openid.credential_persons(credential,person) VALUES(NEW.credential,NEW.person)
  ON CONFLICT(credential) DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM openid.credential_persons
               WHERE credential=NEW.credential AND person=NEW.person) THEN
  RAISE EXCEPTION 'registration person binding mismatch';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION record_profile_person() FROM PUBLIC;
CREATE TRIGGER profile_person_record BEFORE INSERT OR UPDATE OF credential,person ON profiles
 FOR EACH ROW EXECUTE FUNCTION record_profile_person();
REVOKE ALL ON credential_persons FROM PUBLIC;
GRANT SELECT ON credential_persons TO openid_backup;
ALTER TABLE schema_version DROP CONSTRAINT schema_version_version_check;
UPDATE schema_version SET version=6;
ALTER TABLE schema_version ADD CONSTRAINT schema_version_version_check CHECK(version=6);
COMMIT;
