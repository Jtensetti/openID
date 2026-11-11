-- Stop writers and retain a verified schema-7 backup before migrating.
BEGIN;
DO $$
DECLARE existing record;
BEGIN
 SELECT * INTO existing FROM pg_roles WHERE rolname='openid_registry';
 IF NOT FOUND THEN CREATE ROLE openid_registry NOLOGIN;
 ELSIF existing.rolcanlogin OR existing.rolsuper OR existing.rolcreatedb OR existing.rolcreaterole
  OR existing.rolreplication OR existing.rolbypassrls
 THEN RAISE EXCEPTION 'unsafe existing registry group'; END IF;
END $$;
SET LOCAL ROLE openid_owner;
SET LOCAL search_path=openid,pg_catalog;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
LOCK TABLE schema_version IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF (SELECT array_agg(version) FROM schema_version) IS DISTINCT FROM ARRAY[7] THEN
  RAISE EXCEPTION 'schema version 7 required';
 END IF;
END $$;
LOCK TABLE credentials,profiles,activation_proposals IN ACCESS EXCLUSIVE MODE;
CREATE TABLE registry_evidence (
 reference text PRIMARY KEY CHECK(reference ~ '^vault:v1:[A-Za-z0-9+/]{43}=$'),
 credential text NOT NULL REFERENCES credentials(id) ON DELETE CASCADE);
CREATE TABLE registry_bindings (
 credential text PRIMARY KEY REFERENCES profiles(credential) ON DELETE CASCADE,
 person_tag text NOT NULL CHECK(person_tag ~ '^vault:v1:[A-Za-z0-9+/]{43}=$'),
 sealed text NOT NULL CHECK(octet_length(sealed)<=65536),
 source text NOT NULL CHECK(source ~ '^[a-z][a-z0-9-]{2,63}$'),
 identity_kind text NOT NULL CHECK(identity_kind IN ('personnummer','samordningsnummer','synthetic')),
 profile_version text NOT NULL,
 document_reference text NOT NULL,
 checked_at bigint NOT NULL CHECK(checked_at>=0),
 valid_until bigint NOT NULL CHECK(valid_until>checked_at AND valid_until<=checked_at+86400),
 evidence_reference text NOT NULL);
ALTER TABLE activation_proposals ADD COLUMN registry_reference text;
UPDATE activation_proposals SET expires=0 WHERE approved_at IS NULL;
CREATE FUNCTION record_registry_binding(
 target text, person_reference text, sealed_binding text, registry_source text,
 identity_kind text, profile_revision text, document_reference text,
 checked_epoch bigint, until_epoch bigint, evidence_reference text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE c credentials; p profiles; previous registry_bindings; actual_document text;
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
  OR c.id IS NULL OR c.state NOT IN ('PENDING_REVIEW','ACTIVE')
  OR p.credential IS NULL OR p.version IS DISTINCT FROM profile_revision
  OR actual_document IS DISTINCT FROM document_reference
 THEN RAISE EXCEPTION 'registry profile changed'; END IF;
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
 INSERT INTO events(credential,kind,time) VALUES(target,'REGISTRY_CHECKED',now_epoch);
 INSERT INTO operator_events(actor,kind,credential) VALUES(session_user,'REGISTRY_CHECKED',target);
END $$;

CREATE OR REPLACE FUNCTION request_activation(target text, reference text, validity integer) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE c credentials; p profiles; binding registry_bindings; proposal text; now_epoch bigint:=extract(epoch FROM clock_timestamp())::bigint;
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
 IF EXISTS(SELECT 1 FROM activation_proposals WHERE credential=target AND expires>now_epoch AND approved_at IS NULL) THEN
  RAISE EXCEPTION 'proposal already pending'; END IF;
 proposal:=replace(gen_random_uuid()::text||gen_random_uuid()::text,'-','');
 INSERT INTO activation_proposals VALUES(proposal,target,p.version,session_user,reference,validity,now_epoch,now_epoch+3600,NULL,NULL,binding.evidence_reference);
 INSERT INTO operator_events(actor,kind,credential,proposal) VALUES(session_user,'ACTIVATION_REQUESTED',target,proposal);
 RETURN proposal;
END $$;

CREATE OR REPLACE FUNCTION revoke_credential(target text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
BEGIN
 PERFORM 1 FROM credentials WHERE id=target FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'credential unavailable'; END IF;
 UPDATE credentials SET state='REVOKED' WHERE id=target AND state!='REVOKED';
 UPDATE requests SET state='CANCELLED' WHERE credential=target AND state IN ('PENDING','APPROVED');
 UPDATE federation_requests SET state='CANCELLED' WHERE credential=target AND state IN ('PENDING','APPROVED');
 DELETE FROM challenges WHERE credential=target;
 INSERT INTO events(credential,kind,time) VALUES(target,'REVOKED',extract(epoch FROM clock_timestamp())::bigint);
 INSERT INTO operator_events(actor,kind,credential) VALUES(session_user,'REVOKED',target);
END $$;

CREATE OR REPLACE FUNCTION approve_activation(proposal_id text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE proposal activation_proposals; c credentials; p profiles; binding registry_bindings; old_id text;
 now_epoch bigint:=extract(epoch FROM clock_timestamp())::bigint;
BEGIN
 SELECT * INTO proposal FROM activation_proposals WHERE id=proposal_id FOR UPDATE;
 IF proposal.id IS NULL OR proposal.requester=session_user OR proposal.approved_at IS NOT NULL OR proposal.expires<=now_epoch THEN
  RAISE EXCEPTION 'independent unused approval required'; END IF;
 SELECT * INTO p FROM profiles WHERE credential=proposal.credential;
 IF p.credential IS NULL OR p.version!=proposal.profile_version OR p.document_expires<=now_epoch THEN
  RAISE EXCEPTION 'profile unavailable'; END IF;
 -- All replacements for one person use this order: person, then sorted credentials.
 PERFORM 1 FROM persons WHERE id=p.person FOR UPDATE;
 PERFORM 1 FROM credentials WHERE id IN (SELECT credential FROM profiles WHERE person=p.person) ORDER BY id FOR UPDATE;
 SELECT * INTO c FROM credentials WHERE id=proposal.credential;
 SELECT * INTO p FROM profiles WHERE credential=proposal.credential;
 now_epoch:=extract(epoch FROM clock_timestamp())::bigint;
 IF proposal.expires<=now_epoch OR p.credential IS NULL OR p.version!=proposal.profile_version
  OR p.document_expires<=now_epoch THEN RAISE EXCEPTION 'profile unavailable'; END IF;
 IF c.state!='PENDING_REVIEW' OR c.created<now_epoch-86400 THEN RAISE EXCEPTION 'new proofing required'; END IF;
 SELECT * INTO binding FROM registry_bindings WHERE credential=c.id FOR UPDATE;
 IF binding.credential IS NULL OR binding.identity_kind='synthetic'
  OR binding.evidence_reference IS DISTINCT FROM proposal.registry_reference
  OR binding.profile_version!=p.version
  OR binding.document_reference IS DISTINCT FROM (SELECT document_tag FROM persons WHERE id=p.person)
  OR binding.checked_at>now_epoch OR binding.valid_until<=now_epoch
 THEN RAISE EXCEPTION 'fresh unchanged registry evidence required'; END IF;
 FOR old_id IN SELECT credential FROM profiles WHERE person=p.person AND credential!=c.id ORDER BY credential LOOP
  PERFORM revoke_credential(old_id);
 END LOOP;
 UPDATE credentials SET state='ACTIVE',expires=least(now_epoch+proposal.hours*3600,p.document_expires),decision=proposal.decision WHERE id=c.id;
 UPDATE activation_proposals SET approved_by=session_user,approved_at=now_epoch WHERE id=proposal_id;
 INSERT INTO events(credential,kind,time) VALUES(c.id,'ACTIVATED',now_epoch);
 INSERT INTO operator_events(actor,kind,credential,proposal) VALUES(session_user,'ACTIVATED',c.id,proposal_id);
END $$;

-- Deliberate fail-closed restore: run before any service receives access to a restored registry.
CREATE OR REPLACE FUNCTION revoke_all_after_restore() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
BEGIN
 LOCK TABLE credentials,requests,federation_requests,challenges,registry_bindings IN ACCESS EXCLUSIVE MODE;
 INSERT INTO enrollment_quarantine VALUES(1,floor(extract(epoch FROM clock_timestamp()))::bigint+86400)
  ON CONFLICT(id) DO UPDATE SET until_epoch=greatest(enrollment_quarantine.until_epoch,excluded.until_epoch);
 UPDATE credentials SET state='REVOKED';
 UPDATE requests SET state='CANCELLED' WHERE state IN ('PENDING','APPROVED');
 UPDATE federation_requests SET state='CANCELLED' WHERE state IN ('PENDING','APPROVED');
 DELETE FROM challenges;
 -- Restored lookups are historical; keep consumed references to prevent replay.
 DELETE FROM registry_bindings;
 UPDATE activation_proposals SET expires=0 WHERE approved_at IS NULL;
 INSERT INTO operator_events(actor,kind) VALUES(session_user,'RESTORE_REVOKED_ALL');
END $$;

GRANT USAGE ON SCHEMA openid TO openid_registry;
GRANT SELECT ON schema_version,credentials,profiles,persons,registry_bindings TO openid_registry;
GRANT SELECT ON registry_bindings TO openid_wallet,openid_requester,openid_approver,openid_auditor,openid_backup;
GRANT SELECT ON registry_evidence TO openid_auditor,openid_backup;
GRANT EXECUTE ON FUNCTION record_registry_binding(text,text,text,text,text,text,text,bigint,bigint,text) TO openid_registry;
REVOKE ALL ON registry_bindings,registry_evidence FROM PUBLIC;
REVOKE ALL ON FUNCTION record_registry_binding(text,text,text,text,text,text,text,bigint,bigint,text) FROM PUBLIC;
ALTER TABLE schema_version DROP CONSTRAINT schema_version_version_check;
UPDATE schema_version SET version=8;
ALTER TABLE schema_version ADD CONSTRAINT schema_version_version_check CHECK(version=8);
COMMIT;
