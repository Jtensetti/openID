-- Controlled schema-8 to schema-9 transition. Quiesce services and verify a full
-- schema-8 backup first. This migration performs NO external AWS operation.
BEGIN;
DO $$ BEGIN
 IF (SELECT version FROM openid.schema_version) IS DISTINCT FROM 8 THEN
  RAISE EXCEPTION 'schema 8 required'; END IF;
END $$;
DO $$
DECLARE name text; existing record;
BEGIN
 FOREACH name IN ARRAY ARRAY['openid_owner','openid_enroller','openid_wallet','openid_requester',
  'openid_approver','openid_revoker','openid_maintenance','openid_auditor','openid_backup','openid_registry','openid_continuity','openid_contact'] LOOP
  SELECT * INTO existing FROM pg_roles WHERE rolname=name;
  IF NOT FOUND THEN EXECUTE format('CREATE ROLE %I NOLOGIN',name);
  ELSIF existing.rolcanlogin OR existing.rolsuper OR existing.rolcreatedb OR existing.rolcreaterole
    OR existing.rolreplication OR existing.rolbypassrls THEN RAISE EXCEPTION 'unsafe existing group role';
  END IF;
 END LOOP;
END $$;
-- CREATEROLE alone does not allow SET ROLE or inherited ownership on PostgreSQL 16+.
GRANT openid_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
SET ROLE openid_owner;
SET search_path=openid,pg_catalog;
LOCK TABLE credentials,profiles,persons,credential_persons,registry_bindings,activation_proposals
 IN ACCESS EXCLUSIVE MODE;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
-- A fresh issuer namespace is pinned by an administrator before services start.
-- It must never name an old pilot authority. Applications/operators cannot change it.
CREATE TABLE continuity_config(id integer PRIMARY KEY CHECK(id=1), authority text NOT NULL
 CHECK(authority ~ '^arn:aws:lambda:eu-north-1:[0-9]{12}:function:[A-Za-z0-9_-]{1,64}$'));
-- No credential FK: confirmations must commit independently of a holder transaction.
-- These are controller attestations, not cryptographic proof of an AWS response.
CREATE TABLE external_revocations(credential text PRIMARY KEY CHECK(credential ~ '^[a-f0-9]{64}$'),
 authority text NOT NULL, confirmed_at bigint NOT NULL, actor name NOT NULL);
CREATE TABLE notice_contacts(credential text PRIMARY KEY REFERENCES credentials,
 contact_version text NOT NULL CHECK(contact_version ~ '^[A-Za-z0-9_-]{16,128}$'),
 evidence text NOT NULL CHECK(evidence ~ '^[A-Za-z0-9_-]{16,128}$'));
CREATE TABLE revocation_codes(credential text PRIMARY KEY REFERENCES credentials,
 sealed text NOT NULL CHECK(octet_length(sealed)<=65536),
 contact_version text NOT NULL CHECK(contact_version ~ '^[A-Za-z0-9_-]{16,128}$'),
 evidence text NOT NULL CHECK(evidence ~ '^[A-Za-z0-9_-]{16,128}$'));
CREATE TABLE notice_outbox(event text PRIMARY KEY CHECK(event ~ '^[a-f0-9]{64}$'),
 credential text UNIQUE NOT NULL REFERENCES credentials, contact_version text NOT NULL,
 kind text NOT NULL CHECK(kind='ACTIVATED_V1'), created bigint NOT NULL,
 status text NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','QUEUED','CANCELLED')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5), accepted_reference text);
CREATE INDEX notice_outbox_pending ON notice_outbox(status,created,event) WHERE attempts<5;
ALTER TABLE activation_proposals ADD COLUMN contact_version text;
CREATE TABLE approval_intents(id text PRIMARY KEY CHECK(id ~ '^[a-f0-9]{64}$'),
 proposal text UNIQUE NOT NULL REFERENCES activation_proposals, credential text NOT NULL REFERENCES credentials,
 approver name NOT NULL, created bigint NOT NULL, expires bigint NOT NULL,
 completed_by name, completed_at bigint, CHECK((completed_by IS NULL)=(completed_at IS NULL)));
CREATE TABLE intent_revocations(intent text NOT NULL REFERENCES approval_intents,
 credential text NOT NULL CHECK(credential ~ '^[a-f0-9]{64}$'), authority text NOT NULL,
 confirmed_at bigint NOT NULL, PRIMARY KEY(intent,credential));
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
 ELSIF current_user!='openid_owner' AND NEW.state='REVOKED'
  AND NOT EXISTS(SELECT 1 FROM external_revocations WHERE credential=NEW.id
   AND authority=(SELECT authority FROM continuity_config WHERE id=1)) THEN
  RAISE EXCEPTION 'independent revocation not confirmed';
 ELSIF current_user!='openid_owner' AND NEW.state!='REVOKED' THEN
  RAISE EXCEPTION 'activation requires approval';
 ELSIF OLD.state='REVOKED' AND NEW.state!='REVOKED' THEN
  RAISE EXCEPTION 'revocation is permanent';
 END IF;
 RETURN NEW;
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
 IF EXISTS(SELECT 1 FROM activation_proposals WHERE credential=target AND expires>now_epoch AND approved_at IS NULL) THEN
  RAISE EXCEPTION 'proposal already pending'; END IF;
 proposal:=replace(gen_random_uuid()::text||gen_random_uuid()::text,'-','');
 INSERT INTO activation_proposals VALUES(proposal,target,p.version,session_user,reference,validity,now_epoch,now_epoch+3600,NULL,NULL,binding.evidence_reference,contact.contact_version);
 INSERT INTO operator_events(actor,kind,credential,proposal) VALUES(session_user,'ACTIVATION_REQUESTED',target,proposal);
 RETURN proposal;
END $$;

CREATE OR REPLACE FUNCTION revoke_credential(target text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM external_revocations WHERE credential=target
  AND authority=(SELECT authority FROM continuity_config WHERE id=1)) THEN
  RAISE EXCEPTION 'independent revocation not confirmed'; END IF;
 PERFORM 1 FROM credentials WHERE id=target FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'credential unavailable'; END IF;
 UPDATE credentials SET state='REVOKED' WHERE id=target AND state!='REVOKED';
 UPDATE requests SET state='CANCELLED' WHERE credential=target AND state IN ('PENDING','APPROVED');
 UPDATE federation_requests SET state='CANCELLED' WHERE credential=target AND state IN ('PENDING','APPROVED');
 DELETE FROM challenges WHERE credential=target;
 INSERT INTO events(credential,kind,time) VALUES(target,'REVOKED',extract(epoch FROM clock_timestamp())::bigint);
 INSERT INTO operator_events(actor,kind,credential) VALUES(session_user,'REVOKED',target);
END $$;

DROP FUNCTION approve_activation(text);
CREATE FUNCTION approve_activation(proposal_id text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE proposal activation_proposals; p profiles; binding registry_bindings; intent text;
 now_epoch bigint;
BEGIN
 SELECT * INTO proposal FROM activation_proposals WHERE id=proposal_id FOR UPDATE;
 now_epoch:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF proposal.id IS NULL OR proposal.requester=session_user OR proposal.approved_at IS NOT NULL
  OR proposal.expires<=now_epoch OR EXISTS(SELECT 1 FROM approval_intents WHERE proposal=proposal_id) THEN
  RAISE EXCEPTION 'independent unused approval required'; END IF;
 PERFORM 1 FROM credentials WHERE id=proposal.credential AND state='PENDING_REVIEW' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'new proofing required'; END IF;
 SELECT * INTO p FROM profiles WHERE credential=proposal.credential;
 SELECT * INTO binding FROM registry_bindings WHERE credential=proposal.credential FOR UPDATE;
 now_epoch:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p.credential IS NULL OR p.version!=proposal.profile_version OR p.document_expires<=now_epoch THEN
  RAISE EXCEPTION 'profile unavailable'; END IF;
 IF binding.credential IS NULL OR binding.identity_kind='synthetic'
  OR binding.evidence_reference IS DISTINCT FROM proposal.registry_reference
  OR binding.profile_version!=p.version
  OR binding.document_reference IS DISTINCT FROM (SELECT document_tag FROM persons WHERE id=p.person)
  OR binding.checked_at>now_epoch OR binding.valid_until<=now_epoch
 THEN RAISE EXCEPTION 'fresh unchanged registry evidence required'; END IF;
 IF proposal.contact_version IS DISTINCT FROM
  (SELECT contact_version FROM notice_contacts WHERE credential=proposal.credential) THEN
  RAISE EXCEPTION 'unchanged verified contact required'; END IF;
 IF proposal.expires<=now_epoch THEN RAISE EXCEPTION 'approval expired'; END IF;
 intent:=replace(gen_random_uuid()::text||gen_random_uuid()::text,'-','');
 UPDATE activation_proposals SET expires=least(expires,now_epoch+300) WHERE id=proposal_id;
 INSERT INTO approval_intents VALUES(intent,proposal_id,proposal.credential,session_user,now_epoch,
  least(proposal.expires,now_epoch+300),NULL,NULL);
 INSERT INTO operator_events(actor,kind,credential,proposal)
  VALUES(session_user,'ACTIVATION_APPROVED',proposal.credential,proposal_id);
 RETURN intent;
END $$;

CREATE OR REPLACE FUNCTION activation_context(intent_id text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE item approval_intents; proposal activation_proposals; p profiles; c credentials;
 binding registry_bindings; now_epoch bigint; previous text[];
BEGIN
 SELECT * INTO item FROM approval_intents WHERE id=intent_id FOR UPDATE;
 IF item.id IS NULL THEN RAISE EXCEPTION 'approval intent unavailable'; END IF;
 IF item.completed_at IS NOT NULL THEN RETURN jsonb_build_object('completed',true); END IF;
 SELECT * INTO proposal FROM activation_proposals WHERE id=item.proposal FOR UPDATE;
 SELECT * INTO p FROM profiles WHERE credential=item.credential;
 IF p.credential IS NULL THEN RAISE EXCEPTION 'profile unavailable'; END IF;
 -- The present person grouping is a document binding, not yet a cross-passport identity link.
 PERFORM 1 FROM persons WHERE id=p.person FOR UPDATE;
 PERFORM 1 FROM credentials WHERE id IN
  (SELECT credential FROM credential_persons WHERE person=p.person) ORDER BY id FOR UPDATE;
 SELECT * INTO c FROM credentials WHERE id=item.credential;
 SELECT * INTO p FROM profiles WHERE credential=item.credential;
 SELECT * INTO binding FROM registry_bindings WHERE credential=item.credential FOR UPDATE;
 now_epoch:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF item.expires<=now_epoch OR proposal.expires<=now_epoch OR proposal.approved_at IS NOT NULL
  OR item.approver=proposal.requester OR item.credential IS DISTINCT FROM proposal.credential
  OR p.credential IS NULL OR p.version IS DISTINCT FROM proposal.profile_version
  OR p.document_expires<=now_epoch THEN RAISE EXCEPTION 'approval or profile expired'; END IF;
 IF c.state!='PENDING_REVIEW' OR c.created<now_epoch-86400 THEN RAISE EXCEPTION 'new proofing required'; END IF;
 IF binding.credential IS NULL OR binding.identity_kind='synthetic'
  OR binding.evidence_reference IS DISTINCT FROM proposal.registry_reference
  OR binding.profile_version IS DISTINCT FROM p.version
  OR binding.document_reference IS DISTINCT FROM (SELECT document_tag FROM persons WHERE id=p.person)
  OR binding.checked_at>now_epoch OR binding.valid_until<=now_epoch
 THEN RAISE EXCEPTION 'fresh unchanged registry evidence required'; END IF;
 IF proposal.contact_version IS DISTINCT FROM
  (SELECT contact_version FROM notice_contacts WHERE credential=c.id) THEN
  RAISE EXCEPTION 'unchanged verified contact required'; END IF;
 SELECT coalesce(array_agg(credential ORDER BY credential),'{}'::text[]) INTO previous
  FROM credential_persons WHERE person=p.person AND credential!=c.id;
 RETURN jsonb_build_object('completed',false,'credential',c.id,'previous',previous,'confirmed',coalesce(
  (SELECT jsonb_agg(credential ORDER BY credential) FROM intent_revocations WHERE intent=intent_id),'[]'::jsonb));
END $$;

CREATE OR REPLACE FUNCTION activation_snapshot(intent_id text) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
 SELECT activation_context(intent_id);
$$;

CREATE OR REPLACE FUNCTION confirm_external_revocation(target text,source text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
BEGIN
 IF target IS NULL OR target !~ '^[a-f0-9]{64}$' OR source IS NULL
  OR source IS DISTINCT FROM (SELECT authority FROM continuity_config WHERE id=1)
 THEN RAISE EXCEPTION 'pinned authority confirmation required'; END IF;
 INSERT INTO external_revocations VALUES(target,source,
  floor(extract(epoch FROM clock_timestamp()))::bigint,session_user)
  ON CONFLICT(credential) DO NOTHING;
END $$;

CREATE OR REPLACE FUNCTION complete_activation(intent_id text,source text,previous text[]) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE context jsonb; item approval_intents; proposal activation_proposals; old_id text; now_epoch bigint;
BEGIN
 context:=activation_context(intent_id);
 IF (context->>'completed')::boolean THEN RETURN false; END IF;
 IF source IS NULL OR source IS DISTINCT FROM (SELECT authority FROM continuity_config WHERE id=1)
  OR previous IS NULL OR context->'previous' IS DISTINCT FROM to_jsonb(previous)
 THEN RAISE EXCEPTION 'activation snapshot changed'; END IF;
 IF EXISTS(SELECT 1 FROM external_revocations WHERE credential=context->>'credential')
  OR EXISTS(SELECT 1 FROM unnest(previous) key WHERE NOT EXISTS
   (SELECT 1 FROM intent_revocations e WHERE e.intent=intent_id AND e.credential=key AND e.authority=source))
 THEN RAISE EXCEPTION 'independent revocation not confirmed'; END IF;
 SELECT * INTO item FROM approval_intents WHERE id=intent_id;
 SELECT * INTO proposal FROM activation_proposals WHERE id=item.proposal;
 FOR old_id IN SELECT unnest(previous) LOOP PERFORM revoke_credential(old_id); END LOOP;
 now_epoch:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF item.expires<=now_epoch OR proposal.expires<=now_epoch THEN RAISE EXCEPTION 'approval expired'; END IF;
 UPDATE credentials SET state='ACTIVE',
  expires=least(now_epoch+proposal.hours*3600,(SELECT document_expires FROM profiles WHERE credential=item.credential)),
  decision=proposal.decision WHERE id=item.credential;
 INSERT INTO notice_outbox(event,credential,contact_version,kind,created) VALUES
  (encode(sha256(convert_to('activation:v1:'||item.credential,'UTF8')),'hex'),
   item.credential,proposal.contact_version,'ACTIVATED_V1',now_epoch);
 UPDATE activation_proposals SET approved_by=item.approver,approved_at=now_epoch WHERE id=proposal.id;
 UPDATE approval_intents SET completed_by=session_user,completed_at=now_epoch WHERE id=intent_id;
 INSERT INTO events(credential,kind,time) VALUES(item.credential,'ACTIVATED',now_epoch);
 INSERT INTO operator_events(actor,kind,credential,proposal) VALUES(session_user,'ACTIVATED',item.credential,proposal.id);
 RETURN true;
END $$;

CREATE OR REPLACE FUNCTION stage_revocation_contact(target text,sealed_value text,version text,evidence_ref text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
BEGIN
 PERFORM 1 FROM credentials WHERE id=target AND state IN ('PENDING_REVIEW','ACTIVE') FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM profiles WHERE credential=target) THEN
  RAISE EXCEPTION 'verified passport profile required'; END IF;
 INSERT INTO revocation_codes VALUES(target,sealed_value,version,evidence_ref);
END $$;

CREATE OR REPLACE FUNCTION bind_revocation_contact(target text,version text,evidence_ref text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
BEGIN
 PERFORM 1 FROM credentials WHERE id=target AND state IN ('PENDING_REVIEW','ACTIVE') FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM revocation_codes
  WHERE credential=target AND contact_version=version AND evidence=evidence_ref) THEN
  RAISE EXCEPTION 'prepared contact required'; END IF;
 INSERT INTO notice_contacts VALUES(target,version,evidence_ref);
END $$;

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
 UPDATE approval_intents SET expires=0 WHERE completed_at IS NULL;
 UPDATE notice_outbox SET status='CANCELLED' WHERE status='PENDING';
 INSERT INTO operator_events(actor,kind) VALUES(session_user,'RESTORE_REVOKED_ALL');
END $$;

CREATE OR REPLACE FUNCTION confirm_intent_revocation(intent_id text,target text,source text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
BEGIN
 IF source IS NULL OR source IS DISTINCT FROM (SELECT authority FROM continuity_config WHERE id=1)
  OR NOT EXISTS(SELECT 1 FROM external_revocations WHERE credential=target AND authority=source)
 THEN RAISE EXCEPTION 'committed external revocation required'; END IF;
 IF NOT EXISTS(SELECT 1 FROM approval_intents i
  JOIN credential_persons owner ON owner.credential=i.credential
  JOIN credential_persons old ON old.person=owner.person AND old.credential=target AND old.credential!=i.credential
  WHERE i.id=intent_id AND i.completed_at IS NULL AND i.expires>extract(epoch FROM clock_timestamp()))
 THEN RAISE EXCEPTION 'live intent required'; END IF;
 INSERT INTO intent_revocations VALUES(intent_id,target,source,
  floor(extract(epoch FROM clock_timestamp()))::bigint) ON CONFLICT(intent,credential) DO NOTHING;
END $$;

CREATE OR REPLACE FUNCTION purge_expired(profile_days integer,event_days integer,max_batch integer) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE removed bigint:=0; n bigint; item record; now_epoch bigint:=extract(epoch FROM clock_timestamp())::bigint;
BEGIN
 IF profile_days IS NULL OR event_days IS NULL OR max_batch IS NULL OR profile_days NOT BETWEEN 1 AND 3650
  OR event_days NOT BETWEEN 1827 AND 3650 OR max_batch NOT BETWEEN 1 AND 1000 THEN RAISE EXCEPTION 'retention policy required'; END IF;
 DELETE FROM profiles WHERE credential IN (SELECT p.credential FROM profiles p JOIN credentials c ON c.id=p.credential
  WHERE coalesce(c.expires,c.created+86400)<now_epoch-profile_days*86400
  ORDER BY p.credential LIMIT max_batch FOR UPDATE OF p SKIP LOCKED);
 GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
 DELETE FROM security_codes WHERE credential IN (SELECT s.credential FROM security_codes s JOIN credentials c ON c.id=s.credential
  WHERE coalesce(c.expires,c.created+86400)<now_epoch-profile_days*86400
  ORDER BY s.credential LIMIT max_batch FOR UPDATE OF s SKIP LOCKED);
 GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
 FOR item IN SELECT * FROM (VALUES
  ('challenges','expires',now_epoch),('requests','expires',now_epoch-3600),
  ('federation_requests','expires',now_epoch-3600)) AS t(table_name,column_name,cutoff)
 LOOP
  -- Signature text needs its own retention/disclosure decision, as in SQLite.
  EXECUTE format('DELETE FROM %I WHERE id IN (SELECT id FROM %I WHERE %I<$1%s ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED)',
   item.table_name,item.table_name,item.column_name,
   CASE WHEN item.table_name='federation_requests' THEN ' AND sign_message IS NULL' ELSE '' END)
   USING item.cutoff,max_batch;
  GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
 END LOOP;
 DELETE FROM events WHERE id IN (SELECT e.id FROM events e JOIN credentials c ON c.id=e.credential
  WHERE greatest(e.time,coalesce(c.expires,c.created+86400))<now_epoch-event_days::bigint*86400
  ORDER BY e.id LIMIT max_batch FOR UPDATE OF e SKIP LOCKED);
 GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
 DELETE FROM activation_proposals WHERE id IN (SELECT p.id FROM activation_proposals p JOIN credentials c ON c.id=p.credential
  WHERE greatest(p.expires,coalesce(p.approved_at,0),coalesce(c.expires,c.created+86400))<now_epoch-event_days::bigint*86400
  AND NOT EXISTS(SELECT 1 FROM approval_intents i WHERE i.proposal=p.id)
  ORDER BY p.id LIMIT max_batch FOR UPDATE OF p SKIP LOCKED);
 GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
 DELETE FROM biometric_attempts WHERE document_tag IN (SELECT document_tag FROM biometric_attempts
  WHERE times[cardinality(times)]<=now_epoch-86400 ORDER BY document_tag LIMIT max_batch FOR UPDATE SKIP LOCKED);
 GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
 INSERT INTO maintenance_runs VALUES(1,clock_timestamp(),removed)
  ON CONFLICT(id) DO UPDATE SET completed_at=excluded.completed_at,removed=excluded.removed;
 RETURN removed;
END $$;
-- Historical proposals did not bind a verified contact or this authority.
UPDATE activation_proposals SET expires=0 WHERE approved_at IS NULL;
REVOKE EXECUTE ON FUNCTION revoke_all_after_restore() FROM openid_revoker;
GRANT EXECUTE ON FUNCTION approve_activation(text) TO openid_approver;
GRANT EXECUTE ON FUNCTION revoke_credential(text) TO openid_revoker,openid_continuity;
-- Full local restore invalidation is restricted to the owner running isolated recovery.
GRANT USAGE ON SCHEMA openid TO openid_continuity,openid_contact;
GRANT SELECT ON continuity_config TO openid_enroller,openid_wallet,openid_registry,openid_contact,openid_continuity,openid_maintenance;
GRANT SELECT ON schema_version,credentials,profiles,revocation_codes,notice_contacts TO openid_contact;
GRANT EXECUTE ON FUNCTION stage_revocation_contact(text,text,text,text),bind_revocation_contact(text,text,text) TO openid_contact;
GRANT EXECUTE ON FUNCTION activation_snapshot(text),complete_activation(text,text,text[]),
 confirm_external_revocation(text,text),confirm_intent_revocation(text,text,text) TO openid_continuity;
GRANT SELECT ON notice_outbox,notice_contacts,revocation_codes,external_revocations TO openid_wallet;
GRANT UPDATE(status,attempts,accepted_reference) ON notice_outbox TO openid_wallet;
GRANT SELECT ON approval_intents,intent_revocations,external_revocations,notice_contacts,notice_outbox TO openid_auditor;
GRANT SELECT ON ALL TABLES IN SCHEMA openid TO openid_backup;
ALTER TABLE schema_version DROP CONSTRAINT schema_version_version_check;
UPDATE schema_version SET version=9;
ALTER TABLE schema_version ADD CHECK(version=9);
RESET ROLE;
COMMIT;
