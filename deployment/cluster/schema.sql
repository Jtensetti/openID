-- Run once as the database administrator in a new, dedicated database.
BEGIN;
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
CREATE SCHEMA openid AUTHORIZATION openid_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SET ROLE openid_owner;
SET search_path=openid,pg_catalog;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
CREATE TABLE schema_version(version integer PRIMARY KEY CHECK(version=9));
INSERT INTO schema_version VALUES(9);
CREATE TABLE credentials (
 id text PRIMARY KEY CHECK(id ~ '^[a-f0-9]{64}$'), public_key text UNIQUE NOT NULL,
 state text NOT NULL CHECK(state IN ('PENDING_REVIEW','ACTIVE','REVOKED')), created bigint NOT NULL,
 expires bigint, decision text, subject text UNIQUE NOT NULL,
 CHECK(state!='ACTIVE' OR (expires IS NOT NULL AND decision IS NOT NULL)));
CREATE TABLE persons(id text PRIMARY KEY, document_tag text UNIQUE NOT NULL);
CREATE TABLE profiles (
 credential text PRIMARY KEY REFERENCES credentials, person text NOT NULL REFERENCES persons,
 version text UNIQUE NOT NULL, sealed text NOT NULL CHECK(length(sealed)<=65536),
 verified bigint NOT NULL, document_expires bigint NOT NULL);
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
-- Keep the minimum registration/person link after profile-content retention.
-- It remains personal data; this is not a decision about its retention period.
CREATE TABLE credential_persons (
 credential text PRIMARY KEY REFERENCES credentials, person text NOT NULL REFERENCES persons,
 UNIQUE(credential,person));
CREATE INDEX credential_person ON credential_persons(person);
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
CREATE TRIGGER profile_person_record BEFORE INSERT OR UPDATE OF credential,person ON profiles
 FOR EACH ROW EXECUTE FUNCTION record_profile_person();
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
CREATE TRIGGER consent_immutable BEFORE INSERT OR UPDATE ON enrollment_consents FOR EACH ROW EXECUTE FUNCTION guard_consent();
CREATE TABLE requests (
 id text PRIMARY KEY, credential text NOT NULL REFERENCES credentials, secret_hash text NOT NULL,
 state text NOT NULL CHECK(state IN ('PENDING','APPROVED','REJECTED','CANCELLED','CONSUMED')),
 created bigint NOT NULL, expires bigint NOT NULL, code text NOT NULL);
CREATE TABLE federation_requests (
 id text PRIMARY KEY, credential text REFERENCES credentials, secret_hash text NOT NULL,
 state text NOT NULL CHECK(state IN ('PENDING','APPROVED','REJECTED','CANCELLED','CONSUMED')),
 created bigint NOT NULL, expires bigint NOT NULL, code text NOT NULL, binding text NOT NULL, audience text NOT NULL,
 sign_message text CHECK(sign_message IS NULL OR length(sign_message) BETWEEN 1 AND 400),
 level text CHECK(level IS NULL OR level='pin'));
CREATE TABLE events(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, credential text NOT NULL REFERENCES credentials,
 kind text NOT NULL, time bigint NOT NULL, request text);
CREATE TABLE challenges(id text PRIMARY KEY, credential text NOT NULL REFERENCES credentials,
 payload text NOT NULL CHECK(length(payload)<=4096), expires bigint NOT NULL, federation boolean NOT NULL);
CREATE TABLE pairwise_subjects(person text REFERENCES persons, audience text, subject text UNIQUE NOT NULL,
 PRIMARY KEY(person,audience));
CREATE TABLE activation_proposals(id text PRIMARY KEY, credential text REFERENCES credentials, profile_version text NOT NULL,
 requester name NOT NULL, decision text NOT NULL, hours integer NOT NULL CHECK(hours BETWEEN 1 AND 72),
 created bigint NOT NULL, expires bigint NOT NULL, approved_by name, approved_at bigint, registry_reference text);
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
CREATE TABLE operator_events(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, actor name NOT NULL,
 kind text NOT NULL, credential text, proposal text, time timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE maintenance_runs(id integer PRIMARY KEY CHECK(id=1), completed_at timestamptz NOT NULL, removed bigint NOT NULL);
CREATE TABLE biometric_attempts(document_tag text PRIMARY KEY, times bigint[] NOT NULL
 CHECK(cardinality(times) BETWEEN 1 AND 5 AND array_position(times,NULL) IS NULL));
CREATE TABLE security_codes(credential text PRIMARY KEY REFERENCES credentials, hash text NOT NULL CHECK(length(hash)<=256),
 failures integer NOT NULL CHECK(failures BETWEEN 0 AND 5), locked integer NOT NULL CHECK(locked IN (0,1)),
 updated bigint NOT NULL, CHECK((locked=1)=(failures=5)));
CREATE TABLE enrollment_quarantine(id integer PRIMARY KEY CHECK(id=1), until_epoch bigint NOT NULL CHECK(until_epoch>=0));
CREATE INDEX request_pending ON requests(credential,state,expires);
CREATE INDEX event_recent ON events(credential,id DESC);
CREATE INDEX profile_person ON profiles(person);
CREATE INDEX federation_pending ON federation_requests(state,expires);
CREATE INDEX challenge_expiry ON challenges(expires);
CREATE INDEX challenge_credential ON challenges(credential);
CREATE INDEX request_expiry ON requests(expires);
CREATE INDEX federation_expiry ON federation_requests(expires);
CREATE INDEX event_expiry ON events(time);
CREATE INDEX proposal_expiry ON activation_proposals(expires);

-- Only the enroller may spend a budget; no service role can reset or edit it.
-- The tag comes from the separate Transit HMAC key, never the raw document number.
CREATE FUNCTION reserve_biometric_attempt(tag text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE recent bigint[]; now_epoch bigint:=floor(extract(epoch FROM clock_timestamp()))::bigint;
BEGIN
 IF tag IS NULL OR length(tag) NOT BETWEEN 32 AND 256 OR tag !~ '^[A-Za-z0-9_:/+=-]+$' THEN RAISE EXCEPTION 'document tag required'; END IF;
 IF EXISTS(SELECT 1 FROM enrollment_quarantine WHERE until_epoch>now_epoch) THEN RETURN -2; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(tag,7833));
 SELECT coalesce(array_agg(t ORDER BY t),'{}'::bigint[]) INTO recent
  FROM biometric_attempts b CROSS JOIN LATERAL unnest(b.times) t
  WHERE b.document_tag=tag AND t>now_epoch-86400;
 IF cardinality(recent)>=5 THEN RETURN -1; END IF;
 INSERT INTO biometric_attempts VALUES(tag,array_append(recent,now_epoch))
  ON CONFLICT(document_tag) DO UPDATE SET times=excluded.times;
 RETURN 4-cardinality(recent);
END $$;

CREATE FUNCTION security_code_status(target text) RETURNS TABLE(failures integer,locked integer)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
 SELECT failures,locked FROM security_codes WHERE credential=target;
$$;

CREATE FUNCTION check_security_code(target text,candidate text) RETURNS TABLE(code text,remaining integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE item security_codes; failed integer;
BEGIN
 IF target IS NULL OR target !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'credential required'; END IF;
 IF candidate IS NOT NULL AND (length(candidate)>256 OR candidate !~ '^vault:v1:[A-Za-z0-9+/=]+$') THEN
  RAISE EXCEPTION 'code verifier required'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(target,7834));
 SELECT * INTO item FROM security_codes WHERE credential=target FOR UPDATE;
 IF item.credential IS NULL THEN RETURN QUERY SELECT 'PIN_REQUIRED'::text,NULL::integer; RETURN; END IF;
 IF item.locked=1 THEN RETURN QUERY SELECT 'PIN_LOCKED'::text,0; RETURN; END IF;
 IF candidate IS NULL THEN RETURN QUERY SELECT 'PIN_REQUIRED'::text,5-item.failures; RETURN; END IF;
 IF item.hash=candidate THEN
  UPDATE security_codes SET failures=0 WHERE credential=target;
  RETURN QUERY SELECT NULL::text,5; RETURN;
 END IF;
 failed:=item.failures+1;
 UPDATE security_codes SET failures=failed,locked=(failed=5)::integer,
  updated=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE credential=target;
 INSERT INTO events(credential,kind,time) VALUES(target,
  CASE WHEN failed=5 THEN 'SECURITY_CODE_LOCKED' ELSE 'SECURITY_CODE_FAILED' END,
  floor(extract(epoch FROM clock_timestamp()))::bigint);
 RETURN QUERY SELECT CASE WHEN failed=5 THEN 'PIN_LOCKED' ELSE 'PIN_INCORRECT' END,5-failed;
END $$;

CREATE FUNCTION set_security_code(target text,previous text,replacement text) RETURNS TABLE(code text,remaining integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE result record; now_epoch bigint:=floor(extract(epoch FROM clock_timestamp()))::bigint;
BEGIN
 IF replacement IS NULL OR length(replacement)>256 OR replacement !~ '^vault:v1:[A-Za-z0-9+/=]+$' THEN
  RAISE EXCEPTION 'code verifier required'; END IF;
 IF NOT EXISTS(SELECT 1 FROM credentials c JOIN profiles p ON c.id=p.credential
  WHERE c.id=target AND c.state='ACTIVE' AND c.expires>now_epoch AND p.document_expires>now_epoch) THEN
  RAISE EXCEPTION 'verified active credential required'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(target,7834));
 IF EXISTS(SELECT 1 FROM security_codes WHERE credential=target) THEN
  SELECT * INTO result FROM check_security_code(target,previous);
  IF result.code IS NOT NULL THEN RETURN QUERY SELECT result.code::text,result.remaining::integer; RETURN; END IF;
 ELSIF previous IS NOT NULL THEN RAISE EXCEPTION 'unexpected previous code';
 END IF;
 INSERT INTO security_codes VALUES(target,replacement,0,0,now_epoch)
  ON CONFLICT(credential) DO UPDATE SET hash=excluded.hash,failures=0,locked=0,updated=excluded.updated;
 INSERT INTO events(credential,kind,time) VALUES(target,'SECURITY_CODE_SET',now_epoch);
 RETURN QUERY SELECT NULL::text,5;
END $$;

CREATE FUNCTION guard_credential() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,openid,pg_temp AS $$
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
CREATE TRIGGER credential_guard BEFORE INSERT OR UPDATE ON credentials FOR EACH ROW EXECUTE FUNCTION guard_credential();

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

CREATE FUNCTION request_activation(target text, reference text, validity integer) RETURNS text
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

CREATE FUNCTION revoke_credential(target text) RETURNS void
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

-- Both operator decisions are necessary, but only the continuity controller may
-- finish issuance after independently revoking every replaced key.
CREATE FUNCTION approve_activation(proposal_id text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE v_proposal activation_proposals; p profiles; binding registry_bindings; intent text;
 now_epoch bigint;
BEGIN
 SELECT * INTO v_proposal FROM activation_proposals WHERE id=proposal_id FOR UPDATE;
 now_epoch:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF v_proposal.id IS NULL OR v_proposal.requester=session_user OR v_proposal.approved_at IS NOT NULL
  OR v_proposal.expires<=now_epoch OR EXISTS(SELECT 1 FROM approval_intents i WHERE i.proposal=proposal_id) THEN
  RAISE EXCEPTION 'independent unused approval required'; END IF;
 PERFORM 1 FROM credentials WHERE id=v_proposal.credential AND state='PENDING_REVIEW' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'new proofing required'; END IF;
 SELECT * INTO p FROM profiles WHERE credential=v_proposal.credential;
 SELECT * INTO binding FROM registry_bindings WHERE credential=v_proposal.credential FOR UPDATE;
 now_epoch:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p.credential IS NULL OR p.version!=v_proposal.profile_version OR p.document_expires<=now_epoch THEN
  RAISE EXCEPTION 'profile unavailable'; END IF;
 IF binding.credential IS NULL OR binding.identity_kind='synthetic'
  OR binding.evidence_reference IS DISTINCT FROM v_proposal.registry_reference
  OR binding.profile_version!=p.version
  OR binding.document_reference IS DISTINCT FROM (SELECT document_tag FROM persons WHERE id=p.person)
  OR binding.checked_at>now_epoch OR binding.valid_until<=now_epoch
 THEN RAISE EXCEPTION 'fresh unchanged registry evidence required'; END IF;
 IF v_proposal.contact_version IS DISTINCT FROM
  (SELECT contact_version FROM notice_contacts WHERE credential=v_proposal.credential) THEN
  RAISE EXCEPTION 'unchanged verified contact required'; END IF;
 IF v_proposal.expires<=now_epoch THEN RAISE EXCEPTION 'approval expired'; END IF;
 intent:=replace(gen_random_uuid()::text||gen_random_uuid()::text,'-','');
 UPDATE activation_proposals SET expires=least(expires,now_epoch+300) WHERE id=proposal_id;
 INSERT INTO approval_intents VALUES(intent,proposal_id,v_proposal.credential,session_user,now_epoch,
  least(v_proposal.expires,now_epoch+300),NULL,NULL);
 INSERT INTO operator_events(actor,kind,credential,proposal)
  VALUES(session_user,'ACTIVATION_APPROVED',v_proposal.credential,proposal_id);
 RETURN intent;
END $$;

-- Private shared validation: locks last only for this short SQL transaction.
-- No external network calls run while these rows are held.
CREATE FUNCTION activation_context(intent_id text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE item approval_intents; v_proposal activation_proposals; p profiles; c credentials;
 binding registry_bindings; now_epoch bigint; previous text[];
BEGIN
 SELECT * INTO item FROM approval_intents WHERE id=intent_id FOR UPDATE;
 IF item.id IS NULL THEN RAISE EXCEPTION 'approval intent unavailable'; END IF;
 IF item.completed_at IS NOT NULL THEN RETURN jsonb_build_object('completed',true); END IF;
 SELECT * INTO v_proposal FROM activation_proposals WHERE id=item.proposal FOR UPDATE;
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
 IF item.expires<=now_epoch OR v_proposal.expires<=now_epoch OR v_proposal.approved_at IS NOT NULL
  OR item.approver=v_proposal.requester OR item.credential IS DISTINCT FROM v_proposal.credential
  OR p.credential IS NULL OR p.version IS DISTINCT FROM v_proposal.profile_version
  OR p.document_expires<=now_epoch THEN RAISE EXCEPTION 'approval or profile expired'; END IF;
 IF c.state!='PENDING_REVIEW' OR c.created<now_epoch-86400 THEN RAISE EXCEPTION 'new proofing required'; END IF;
 IF binding.credential IS NULL OR binding.identity_kind='synthetic'
  OR binding.evidence_reference IS DISTINCT FROM v_proposal.registry_reference
  OR binding.profile_version IS DISTINCT FROM p.version
  OR binding.document_reference IS DISTINCT FROM (SELECT document_tag FROM persons WHERE id=p.person)
  OR binding.checked_at>now_epoch OR binding.valid_until<=now_epoch
 THEN RAISE EXCEPTION 'fresh unchanged registry evidence required'; END IF;
 IF v_proposal.contact_version IS DISTINCT FROM
  (SELECT contact_version FROM notice_contacts WHERE credential=c.id) THEN
  RAISE EXCEPTION 'unchanged verified contact required'; END IF;
 SELECT coalesce(array_agg(credential ORDER BY credential),'{}'::text[]) INTO previous
  FROM credential_persons WHERE person=p.person AND credential!=c.id;
 RETURN jsonb_build_object('completed',false,'credential',c.id,'previous',previous,'confirmed',coalesce(
  (SELECT jsonb_agg(credential ORDER BY credential) FROM intent_revocations WHERE intent=intent_id),'[]'::jsonb));
END $$;

CREATE FUNCTION activation_snapshot(intent_id text) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
 SELECT activation_context(intent_id);
$$;

CREATE FUNCTION confirm_external_revocation(target text,source text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
BEGIN
 IF target IS NULL OR target !~ '^[a-f0-9]{64}$' OR source IS NULL
  OR source IS DISTINCT FROM (SELECT authority FROM continuity_config WHERE id=1)
 THEN RAISE EXCEPTION 'pinned authority confirmation required'; END IF;
 INSERT INTO external_revocations VALUES(target,source,
  floor(extract(epoch FROM clock_timestamp()))::bigint,session_user)
  ON CONFLICT(credential) DO NOTHING;
END $$;

CREATE FUNCTION confirm_intent_revocation(intent_id text,target text,source text) RETURNS void
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

CREATE FUNCTION complete_activation(intent_id text,source text,previous text[]) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE context jsonb; item approval_intents; v_proposal activation_proposals; old_id text; now_epoch bigint;
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
 SELECT * INTO v_proposal FROM activation_proposals WHERE id=item.proposal;
 FOR old_id IN SELECT unnest(previous) LOOP PERFORM revoke_credential(old_id); END LOOP;
 now_epoch:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF item.expires<=now_epoch OR v_proposal.expires<=now_epoch THEN RAISE EXCEPTION 'approval expired'; END IF;
 UPDATE credentials SET state='ACTIVE',
  expires=least(now_epoch+v_proposal.hours*3600,(SELECT document_expires FROM profiles WHERE credential=item.credential)),
  decision=v_proposal.decision WHERE id=item.credential;
 INSERT INTO notice_outbox(event,credential,contact_version,kind,created) VALUES
  (encode(sha256(convert_to('activation:v1:'||item.credential,'UTF8')),'hex'),
   item.credential,v_proposal.contact_version,'ACTIVATED_V1',now_epoch);
 UPDATE activation_proposals SET approved_by=item.approver,approved_at=now_epoch WHERE id=v_proposal.id;
 UPDATE approval_intents SET completed_by=session_user,completed_at=now_epoch WHERE id=intent_id;
 INSERT INTO events(credential,kind,time) VALUES(item.credential,'ACTIVATED',now_epoch);
 INSERT INTO operator_events(actor,kind,credential,proposal) VALUES(session_user,'ACTIVATED',item.credential,v_proposal.id);
 RETURN true;
END $$;

-- Separately authorized contact preparation cannot activate or redirect a binding.
CREATE FUNCTION stage_revocation_contact(target text,sealed_value text,version text,evidence_ref text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
BEGIN
 PERFORM 1 FROM credentials WHERE id=target AND state IN ('PENDING_REVIEW','ACTIVE') FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM profiles WHERE credential=target) THEN
  RAISE EXCEPTION 'verified passport profile required'; END IF;
 INSERT INTO revocation_codes VALUES(target,sealed_value,version,evidence_ref);
END $$;
CREATE FUNCTION bind_revocation_contact(target text,version text,evidence_ref text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
BEGIN
 PERFORM 1 FROM credentials WHERE id=target AND state IN ('PENDING_REVIEW','ACTIVE') FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM revocation_codes
  WHERE credential=target AND contact_version=version AND evidence=evidence_ref) THEN
  RAISE EXCEPTION 'prepared contact required'; END IF;
 INSERT INTO notice_contacts VALUES(target,version,evidence_ref);
END $$;

-- Deliberate fail-closed restore: run before any service receives access to a restored registry.
CREATE FUNCTION revoke_all_after_restore() RETURNS void
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

CREATE FUNCTION purge_expired(profile_days integer,event_days integer,max_batch integer) RETURNS bigint
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

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openid FROM PUBLIC;

GRANT USAGE ON SCHEMA openid TO openid_enroller,openid_wallet,openid_requester,openid_approver,openid_revoker,openid_maintenance,openid_auditor;
GRANT SELECT ON schema_version TO openid_enroller,openid_wallet,openid_maintenance;
GRANT SELECT ON credentials,profiles,persons TO openid_enroller,openid_wallet,openid_maintenance;
GRANT SELECT ON enrollment_quarantine TO openid_enroller;
GRANT INSERT ON credentials,profiles,persons,events TO openid_enroller;
GRANT SELECT,INSERT,DELETE ON challenges TO openid_wallet;
GRANT SELECT,INSERT ON requests,federation_requests,pairwise_subjects TO openid_wallet;
GRANT UPDATE(state) ON requests TO openid_wallet;
GRANT UPDATE(state,credential) ON federation_requests TO openid_wallet;
GRANT SELECT,INSERT ON events TO openid_wallet;
GRANT UPDATE(state) ON credentials TO openid_wallet;
GRANT USAGE ON SEQUENCE events_id_seq TO openid_enroller,openid_wallet;
GRANT USAGE ON SCHEMA openid TO openid_registry;
GRANT SELECT ON schema_version,credentials,profiles,persons,registry_bindings TO openid_registry;
GRANT SELECT ON registry_bindings TO openid_wallet,openid_requester,openid_approver,openid_auditor,openid_backup;
GRANT SELECT ON registry_evidence TO openid_auditor,openid_backup;
GRANT EXECUTE ON FUNCTION record_registry_binding(text,text,text,text,text,text,text,bigint,bigint,text) TO openid_registry;
GRANT SELECT ON operator_events TO openid_auditor;
GRANT SELECT ON activation_proposals TO openid_requester,openid_approver,openid_auditor;
GRANT EXECUTE ON FUNCTION request_activation(text,text,integer) TO openid_requester;
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
GRANT SELECT ON requests,federation_requests,challenges,events,activation_proposals TO openid_maintenance;
GRANT UPDATE(sealed) ON profiles TO openid_maintenance;
GRANT EXECUTE ON FUNCTION purge_expired(integer,integer,integer) TO openid_maintenance;
GRANT EXECUTE ON FUNCTION reserve_biometric_attempt(text) TO openid_enroller;
GRANT EXECUTE ON FUNCTION security_code_status(text),check_security_code(text,text),set_security_code(text,text,text) TO openid_wallet;
GRANT SELECT ON maintenance_runs TO openid_maintenance;
GRANT USAGE ON SCHEMA openid TO openid_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA openid TO openid_backup;
GRANT SELECT,INSERT ON enrollment_policies,enrollment_consents,credential_consents TO openid_enroller;
GRANT UPDATE(withdrawn) ON enrollment_consents TO openid_enroller;
GRANT SELECT ON enrollment_policies,enrollment_consents,credential_consents TO openid_backup;
CREATE TABLE consent_retention_runs(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 time bigint NOT NULL, policy text NOT NULL CHECK(octet_length(policy)<=131072),
 policy_sha256 text NOT NULL CHECK(policy_sha256 ~ '^[a-f0-9]{64}$'), counts text NOT NULL);
CREATE FUNCTION retain_consent_evidence(raw_policy text,apply_changes boolean,max_batch integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $function$
DECLARE p jsonb; held text[]; ids text[]:='{}'; policies text[]:='{}'; chosen record;
 now_epoch bigint:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 unbound_days integer; bound_days integer; canonical_policy text; digest text;
 selection text; counts jsonb; result jsonb; links integer; changed integer; journal bigint;
 more_rows boolean:=false;
BEGIN
 IF apply_changes IS NULL OR max_batch IS NULL OR max_batch NOT BETWEEN 1 AND 1000
    OR raw_policy IS NULL OR octet_length(raw_policy)>131072 THEN RAISE EXCEPTION 'retention input'; END IF;
 p:=raw_policy::jsonb;
 IF jsonb_typeof(p) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'retention policy'; END IF;
 IF (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(p) k)
      IS DISTINCT FROM ARRAY['boundDays','protectedReceipts','reference','regime','unboundDays','version']
    OR p->'version' IS DISTINCT FROM '1'::jsonb
    OR jsonb_typeof(p->'reference') IS DISTINCT FROM 'string' OR p->>'reference' !~ '^[A-Za-z0-9_-]{8,96}$'
    OR p->>'regime' NOT IN ('private-beta','digg')
    OR jsonb_typeof(p->'unboundDays') IS DISTINCT FROM 'number' OR p->>'unboundDays' !~ '^[1-9][0-9]{0,3}$'
    OR jsonb_typeof(p->'boundDays') IS DISTINCT FROM 'number' OR p->>'boundDays' !~ '^[1-9][0-9]{0,3}$'
    OR jsonb_typeof(p->'protectedReceipts') IS DISTINCT FROM 'array'
 THEN RAISE EXCEPTION 'retention policy'; END IF;
 unbound_days:=(p->>'unboundDays')::integer;bound_days:=(p->>'boundDays')::integer;
 IF unbound_days NOT BETWEEN 1 AND 3650 OR bound_days NOT BETWEEN 1 AND 3650
    OR (p->>'regime'='digg' AND bound_days<1827)
    OR jsonb_array_length(p->'protectedReceipts')>1000
    OR EXISTS(SELECT 1 FROM jsonb_array_elements(p->'protectedReceipts') v
       WHERE jsonb_typeof(v)!='string' OR v#>>'{}' !~ '^[a-f0-9]{64}$')
 THEN RAISE EXCEPTION 'retention periods or holds'; END IF;
 held:=ARRAY(SELECT jsonb_array_elements_text(p->'protectedReceipts'));
 IF cardinality(held)!=(SELECT count(DISTINCT v) FROM unnest(held) v) THEN RAISE EXCEPTION 'duplicate holds'; END IF;
 canonical_policy:='{"boundDays":'||bound_days||',"protectedReceipts":'||array_to_json(held)::text||
   ',"reference":"'||(p->>'reference')||'","regime":"'||(p->>'regime')||
   '","unboundDays":'||unbound_days||',"version":1}';
 IF raw_policy IS DISTINCT FROM canonical_policy THEN RAISE EXCEPTION 'canonical policy required'; END IF;
 digest:=encode(sha256(convert_to(canonical_policy,'UTF8')),'hex');
 selection:=$query$SELECT e.id,b.credential FROM openid.enrollment_consents e
   LEFT JOIN openid.credential_consents b ON b.receipt=e.id LEFT JOIN openid.credentials c ON c.id=b.credential
   WHERE e.accepted BETWEEN 0 AND $1 AND (e.withdrawn IS NULL OR e.withdrawn BETWEEN e.accepted AND $1)
     AND ((b.receipt IS NULL AND greatest(e.accepted+300,coalesce(e.withdrawn,0))<$2)
       OR (b.receipt IS NOT NULL AND c.created BETWEEN 0 AND $1
         AND ((c.expires IS NULL AND c.state IN ('PENDING_REVIEW','REVOKED'))
            OR (c.expires>=c.created AND c.state IN ('ACTIVE','REVOKED')))
         AND greatest(e.accepted,coalesce(e.withdrawn,0),coalesce(c.expires,c.created+86400),
           coalesce((SELECT max(time) FROM openid.events WHERE credential=c.id),0))<$3))
     AND NOT (e.id=ANY($4)) ORDER BY e.id LIMIT $5$query$;
 IF apply_changes THEN selection:=selection||' FOR UPDATE OF e SKIP LOCKED'; END IF;
 FOR chosen IN EXECUTE selection USING now_epoch,now_epoch-unbound_days::bigint*86400,
     now_epoch-bound_days::bigint*86400,held,max_batch+1 LOOP
   IF cardinality(ids)=max_batch THEN more_rows:=true;EXIT;END IF;
   IF apply_changes AND chosen.credential IS NOT NULL THEN
     -- Serialize with revocation/activation, then use a fresh statement snapshot.
     -- A revocation committed while we waited must protect its receipt.
     PERFORM 1 FROM openid.credentials WHERE id=chosen.credential FOR UPDATE;
     IF NOT EXISTS(SELECT 1 FROM openid.enrollment_consents e
       JOIN openid.credentials c ON c.id=chosen.credential WHERE e.id=chosen.id
       AND c.created BETWEEN 0 AND now_epoch
       AND ((c.expires IS NULL AND c.state IN ('PENDING_REVIEW','REVOKED'))
          OR (c.expires>=c.created AND c.state IN ('ACTIVE','REVOKED')))
       AND greatest(e.accepted,coalesce(e.withdrawn,0),coalesce(c.expires,c.created+86400),
         coalesce((SELECT max(time) FROM openid.events WHERE credential=c.id),0))
           <now_epoch-bound_days::bigint*86400) THEN CONTINUE;END IF;
   END IF;
   ids:=array_append(ids,chosen.id);
 END LOOP;
 selection:=$query$SELECT p.digest FROM openid.enrollment_policies p
   WHERE (p.record::jsonb->'notice'->>'notAfter')::bigint BETWEEN 0 AND $1
     AND NOT EXISTS(SELECT 1 FROM openid.enrollment_consents e WHERE e.policy_digest=p.digest AND NOT(e.id=ANY($2)))
   ORDER BY p.digest LIMIT $3$query$;
 IF apply_changes THEN selection:=selection||' FOR UPDATE OF p SKIP LOCKED'; END IF;
 FOR chosen IN EXECUTE selection USING now_epoch,ids,max_batch+1 LOOP
   IF cardinality(policies)=max_batch THEN more_rows:=true;EXIT;END IF;
   policies:=array_append(policies,chosen.digest);
 END LOOP;
 SELECT count(*) INTO links FROM openid.credential_consents WHERE receipt=ANY(ids);
 counts:=jsonb_build_object('credential_consents',links,'enrollment_consents',cardinality(ids),'enrollment_policies',cardinality(policies));
 result:=jsonb_build_object('mode',CASE WHEN apply_changes THEN 'apply' ELSE 'plan' END,'time',now_epoch,
   'policyReference',p->>'reference','policySHA256',digest,'selected',counts,'moreEligible',more_rows,'batch',max_batch);
 IF apply_changes THEN
   DELETE FROM openid.credential_consents WHERE receipt=ANY(ids);
   GET DIAGNOSTICS changed=ROW_COUNT;IF changed!=links THEN RAISE EXCEPTION 'binding count mismatch';END IF;
   DELETE FROM openid.enrollment_consents WHERE id=ANY(ids);
   GET DIAGNOSTICS changed=ROW_COUNT;IF changed!=cardinality(ids) THEN RAISE EXCEPTION 'receipt count mismatch';END IF;
   DELETE FROM openid.enrollment_policies WHERE enrollment_policies.digest=ANY(policies);
   GET DIAGNOSTICS changed=ROW_COUNT;IF changed!=cardinality(policies) THEN RAISE EXCEPTION 'policy count mismatch';END IF;
   INSERT INTO openid.consent_retention_runs(time,policy,policy_sha256,counts)
     VALUES(now_epoch,canonical_policy,digest,counts::text) RETURNING id INTO journal;
   result:=result||jsonb_build_object('journalId',journal);
 END IF;
 RETURN result;
END $function$;
REVOKE ALL ON FUNCTION retain_consent_evidence(text,boolean,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION retain_consent_evidence(text,boolean,integer) TO openid_maintenance;
GRANT SELECT ON consent_retention_runs TO openid_maintenance,openid_backup;
RESET ROLE;
COMMIT;
