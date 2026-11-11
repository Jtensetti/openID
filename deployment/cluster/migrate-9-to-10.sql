-- Controlled schema-9 to schema-10 transition. Quiesce services and verify a
-- full schema-9 backup first. No provider call or active-credential revocation.
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
LOCK TABLE openid.schema_version IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF (SELECT version FROM openid.schema_version) IS DISTINCT FROM 9 THEN
  RAISE EXCEPTION 'schema 9 required'; END IF;
END $$;
GRANT openid_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
SET ROLE openid_owner;
SET search_path=openid,pg_catalog;
LOCK TABLE credentials,profiles,persons,registry_bindings,activation_proposals,approval_intents
 IN ACCESS EXCLUSIVE MODE;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;


CREATE TABLE registry_checks (
 credential text PRIMARY KEY REFERENCES profiles(credential) ON DELETE CASCADE,
 nonce text NOT NULL CHECK(nonce ~ '^[a-f0-9]{64}$'),
 profile_version text NOT NULL, document_reference text NOT NULL,
 started_at bigint NOT NULL CHECK(started_at>=0));

CREATE FUNCTION invalidate_registry_binding(target text,expected_profile text,
 expected_document text,expected_evidence text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE c credentials; p profiles; previous registry_bindings; actual_document text;
 generation text; now_epoch bigint;
BEGIN
 SELECT * INTO c FROM credentials WHERE id=target FOR UPDATE;
 SELECT * INTO p FROM profiles WHERE credential=target;
 SELECT document_tag INTO actual_document FROM persons WHERE id=p.person;
 SELECT * INTO previous FROM registry_bindings WHERE credential=target FOR UPDATE;
 IF c.id IS NULL OR c.state!='PENDING_REVIEW' OR p.credential IS NULL
  OR expected_profile IS NULL OR p.version IS DISTINCT FROM expected_profile
  OR expected_document IS NULL OR actual_document IS DISTINCT FROM expected_document
  OR previous.evidence_reference IS DISTINCT FROM expected_evidence
 THEN RAISE EXCEPTION 'registry profile or evidence changed'; END IF;
 now_epoch:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 generation:=replace(gen_random_uuid()::text||gen_random_uuid()::text,'-','');
 -- Keep identity and consumed references; expire only the issuance proof.
 UPDATE registry_bindings SET checked_at=0,valid_until=1 WHERE credential=target;
 INSERT INTO registry_checks VALUES(target,generation,p.version,actual_document,now_epoch)
  ON CONFLICT(credential) DO UPDATE SET nonce=excluded.nonce,
   profile_version=excluded.profile_version,document_reference=excluded.document_reference,
   started_at=excluded.started_at;
 INSERT INTO events(credential,kind,time) VALUES(target,'REGISTRY_CHECK_STARTED',now_epoch);
 INSERT INTO operator_events(actor,kind,credential) VALUES(session_user,'REGISTRY_CHECK_STARTED',target);
 RETURN generation;
END $$;

DROP FUNCTION record_registry_binding(text,text,text,text,text,text,text,bigint,bigint,text);

CREATE FUNCTION record_registry_binding(
 target text, person_reference text, sealed_binding text, registry_source text,
 identity_kind text, profile_revision text, document_reference text,
 checked_epoch bigint, until_epoch bigint, evidence_reference text,check_nonce text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE c credentials; p profiles; previous registry_bindings; actual_document text; attempt registry_checks;
 inserted_reference text; now_epoch bigint:=extract(epoch FROM clock_timestamp())::bigint;
BEGIN
 IF checked_epoch IS NULL OR until_epoch IS NULL OR checked_epoch<0
  OR checked_epoch>now_epoch OR until_epoch<=now_epoch OR until_epoch>checked_epoch+86400
  OR registry_source IS NULL OR registry_source !~ '^[a-z][a-z0-9-]{2,63}$'
  OR identity_kind IS NULL OR identity_kind NOT IN ('personnummer','samordningsnummer','synthetic')
  OR person_reference IS NULL OR person_reference !~ '^vault:v1:[A-Za-z0-9+/]{43}=$'
  OR evidence_reference IS NULL OR evidence_reference !~ '^vault:v1:[A-Za-z0-9+/]{43}=$'
  OR sealed_binding IS NULL OR octet_length(sealed_binding)>65536
 THEN RAISE EXCEPTION 'valid registry evidence required'; END IF;
 SELECT * INTO c FROM credentials WHERE id=target FOR UPDATE;
 now_epoch:=extract(epoch FROM clock_timestamp())::bigint;
 SELECT * INTO p FROM profiles WHERE credential=target;
 SELECT document_tag INTO actual_document FROM persons WHERE id=p.person;
 IF checked_epoch>now_epoch OR until_epoch<=now_epoch
  OR c.id IS NULL OR c.state!='PENDING_REVIEW'
  OR p.credential IS NULL OR p.version IS DISTINCT FROM profile_revision
  OR actual_document IS DISTINCT FROM document_reference
 THEN RAISE EXCEPTION 'registry profile changed'; END IF;
 SELECT * INTO attempt FROM registry_checks WHERE credential=target FOR UPDATE;
 IF check_nonce IS NULL OR check_nonce !~ '^[a-f0-9]{64}$'
  OR attempt.credential IS NULL OR attempt.nonce IS DISTINCT FROM check_nonce
  OR attempt.profile_version IS DISTINCT FROM profile_revision
  OR attempt.document_reference IS DISTINCT FROM document_reference
  OR checked_epoch<attempt.started_at
  OR now_epoch<attempt.started_at OR now_epoch>=attempt.started_at+300
 THEN RAISE EXCEPTION 'current registry check required'; END IF;
 SELECT * INTO previous FROM registry_bindings WHERE credential=target FOR UPDATE;
 IF previous.credential IS NOT NULL AND
  (previous.person_tag!=person_reference OR previous.source!=registry_source OR previous.identity_kind!=identity_kind)
 THEN RAISE EXCEPTION 'registry identity conflict'; END IF;
 INSERT INTO registry_evidence(reference,credential) VALUES(evidence_reference,target)
  ON CONFLICT(reference) DO NOTHING RETURNING reference INTO inserted_reference;
 IF inserted_reference IS NULL THEN RAISE EXCEPTION 'registry evidence already used'; END IF;
 INSERT INTO registry_bindings(credential,person_tag,sealed,source,identity_kind,profile_version,
  document_reference,checked_at,valid_until,evidence_reference)
 VALUES(target,person_reference,sealed_binding,registry_source,identity_kind,profile_revision,
  document_reference,checked_epoch,until_epoch,evidence_reference)
 ON CONFLICT(credential) DO UPDATE SET
  sealed=excluded.sealed,profile_version=excluded.profile_version,
  document_reference=excluded.document_reference,checked_at=excluded.checked_at,
  valid_until=excluded.valid_until,evidence_reference=excluded.evidence_reference;
 DELETE FROM registry_checks WHERE credential=target;
 INSERT INTO events(credential,kind,time) VALUES(target,'REGISTRY_CHECKED',now_epoch);
 INSERT INTO operator_events(actor,kind,credential) VALUES(session_user,'REGISTRY_CHECKED',target);
END $$;

CREATE OR REPLACE FUNCTION request_activation(target text, reference text, validity integer) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE c credentials; p profiles; binding registry_bindings; contact notice_contacts; proposal text; now_epoch bigint:=extract(epoch FROM clock_timestamp())::bigint;
BEGIN
 IF reference !~ '^[A-Za-z0-9_-]{8,80}$' OR validity NOT BETWEEN 1 AND 72 OR validity IS NULL THEN
  RAISE EXCEPTION 'invalid decision';
 END IF;
 SELECT * INTO c FROM credentials WHERE id=target FOR UPDATE;
 SELECT * INTO p FROM profiles WHERE credential=target;
 SELECT * INTO binding FROM registry_bindings WHERE credential=target FOR UPDATE;
 now_epoch:=extract(epoch FROM clock_timestamp())::bigint;
 IF c.id IS NULL OR p.credential IS NULL OR c.state!='PENDING_REVIEW' OR c.created<now_epoch-86400
  OR p.document_expires<=now_epoch THEN RAISE EXCEPTION 'new proofing required'; END IF;
 IF binding.credential IS NULL OR binding.identity_kind='synthetic'
  OR binding.profile_version!=p.version
  OR binding.document_reference IS DISTINCT FROM (SELECT document_tag FROM persons WHERE id=p.person)
  OR binding.checked_at>now_epoch OR binding.valid_until<=now_epoch
 THEN RAISE EXCEPTION 'fresh registry evidence required'; END IF;
 SELECT * INTO contact FROM notice_contacts WHERE credential=target;
 IF contact.credential IS NULL THEN RAISE EXCEPTION 'separately verified contact required'; END IF;
 IF NOT EXISTS(SELECT 1 FROM continuity_config WHERE id=1) THEN RAISE EXCEPTION 'continuity authority required'; END IF;
 IF EXISTS(SELECT 1 FROM activation_proposals WHERE credential=target AND expires>now_epoch
  AND approved_at IS NULL AND registry_reference=binding.evidence_reference) THEN
  RAISE EXCEPTION 'proposal already pending'; END IF;
 proposal:=replace(gen_random_uuid()::text||gen_random_uuid()::text,'-','');
 INSERT INTO activation_proposals VALUES(proposal,target,p.version,session_user,reference,validity,now_epoch,now_epoch+3600,NULL,NULL,binding.evidence_reference,contact.contact_version);
 INSERT INTO operator_events(actor,kind,credential,proposal) VALUES(session_user,'ACTIVATION_REQUESTED',target,proposal);
 RETURN proposal;
END $$;

CREATE OR REPLACE FUNCTION revoke_all_after_restore() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
BEGIN
 LOCK TABLE credentials,requests,federation_requests,challenges,registry_bindings,registry_checks IN ACCESS EXCLUSIVE MODE;
 INSERT INTO enrollment_quarantine VALUES(1,floor(extract(epoch FROM clock_timestamp()))::bigint+86400)
  ON CONFLICT(id) DO UPDATE SET until_epoch=greatest(enrollment_quarantine.until_epoch,excluded.until_epoch);
 UPDATE credentials SET state='REVOKED';
 UPDATE requests SET state='CANCELLED' WHERE state IN ('PENDING','APPROVED');
 UPDATE federation_requests SET state='CANCELLED' WHERE state IN ('PENDING','APPROVED');
 DELETE FROM challenges;
 -- Restored lookups are historical; keep consumed references to prevent replay.
 DELETE FROM registry_checks;
 DELETE FROM registry_bindings;
 UPDATE activation_proposals SET expires=0 WHERE approved_at IS NULL;
 UPDATE approval_intents SET expires=0 WHERE completed_at IS NULL;
 UPDATE notice_outbox SET status='CANCELLED' WHERE status='PENDING';
 INSERT INTO operator_events(actor,kind) VALUES(session_user,'RESTORE_REVOKED_ALL');
END $$;

-- Pre-migration pending evidence has no durable lookup generation.
UPDATE registry_bindings SET checked_at=0,valid_until=1 WHERE credential IN
 (SELECT id FROM credentials WHERE state='PENDING_REVIEW');
UPDATE activation_proposals SET expires=0 WHERE approved_at IS NULL;
UPDATE approval_intents SET expires=0 WHERE completed_at IS NULL;
REVOKE ALL ON FUNCTION invalidate_registry_binding(text,text,text,text),
 record_registry_binding(text,text,text,text,text,text,text,bigint,bigint,text,text) FROM PUBLIC;
GRANT SELECT ON registry_bindings TO openid_registry;
GRANT SELECT ON registry_checks TO openid_auditor,openid_backup;
GRANT EXECUTE ON FUNCTION invalidate_registry_binding(text,text,text,text),
 record_registry_binding(text,text,text,text,text,text,text,bigint,bigint,text,text) TO openid_registry;
ALTER TABLE schema_version DROP CONSTRAINT schema_version_version_check;
UPDATE schema_version SET version=10;
ALTER TABLE schema_version ADD CHECK(version=10);
RESET ROLE;
COMMIT;
