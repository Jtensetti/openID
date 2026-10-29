-- Run once as the database administrator in a new, dedicated database.
BEGIN;
DO $$
DECLARE name text; existing record;
BEGIN
 FOREACH name IN ARRAY ARRAY['openid_owner','openid_enroller','openid_wallet','openid_requester',
  'openid_approver','openid_revoker','openid_maintenance','openid_auditor','openid_backup'] LOOP
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
CREATE TABLE schema_version(version integer PRIMARY KEY CHECK(version=6));
INSERT INTO schema_version VALUES(6);
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
-- Keep the minimum registration/person link after profile-content retention.
-- It remains personal data; this is not a decision about its retention period.
CREATE TABLE credential_persons (
 credential text PRIMARY KEY REFERENCES credentials, person text NOT NULL REFERENCES persons,
 UNIQUE(credential,person));
CREATE INDEX credential_person ON credential_persons(person);
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
 IF ROW(NEW.id,NEW.subject,NEW.policy_digest,NEW.accepted,NEW.proof)
      IS DISTINCT FROM ROW(OLD.id,OLD.subject,OLD.policy_digest,OLD.accepted,OLD.proof)
    OR NEW.withdrawn IS NULL OR (OLD.withdrawn IS NOT NULL AND NEW.withdrawn IS DISTINCT FROM OLD.withdrawn)
 THEN RAISE EXCEPTION 'consent evidence is immutable; withdrawal is permanent'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER consent_immutable BEFORE UPDATE ON enrollment_consents FOR EACH ROW EXECUTE FUNCTION guard_consent();
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
 created bigint NOT NULL, expires bigint NOT NULL, approved_by name, approved_at bigint);
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
CREATE TRIGGER credential_guard BEFORE INSERT OR UPDATE ON credentials FOR EACH ROW EXECUTE FUNCTION guard_credential();

CREATE FUNCTION request_activation(target text, reference text, validity integer) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE c credentials; p profiles; proposal text; now_epoch bigint:=extract(epoch FROM clock_timestamp())::bigint;
BEGIN
 IF reference !~ '^[A-Za-z0-9_-]{8,80}$' OR validity NOT BETWEEN 1 AND 72 OR validity IS NULL THEN
  RAISE EXCEPTION 'invalid decision';
 END IF;
 SELECT * INTO c FROM credentials WHERE id=target FOR UPDATE;
 SELECT * INTO p FROM profiles WHERE credential=target;
 IF c.id IS NULL OR p.credential IS NULL OR c.state!='PENDING_REVIEW' OR c.created<now_epoch-86400
  OR p.document_expires<=now_epoch THEN RAISE EXCEPTION 'new proofing required'; END IF;
 IF EXISTS(SELECT 1 FROM activation_proposals WHERE credential=target AND expires>now_epoch AND approved_at IS NULL) THEN
  RAISE EXCEPTION 'proposal already pending'; END IF;
 proposal:=replace(gen_random_uuid()::text||gen_random_uuid()::text,'-','');
 INSERT INTO activation_proposals VALUES(proposal,target,p.version,session_user,reference,validity,now_epoch,now_epoch+3600,NULL,NULL);
 INSERT INTO operator_events(actor,kind,credential,proposal) VALUES(session_user,'ACTIVATION_REQUESTED',target,proposal);
 RETURN proposal;
END $$;

CREATE FUNCTION revoke_credential(target text) RETURNS void
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

CREATE FUNCTION approve_activation(proposal_id text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE proposal activation_proposals; c credentials; p profiles; old_id text;
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
 IF c.state!='PENDING_REVIEW' OR c.created<now_epoch-86400 THEN RAISE EXCEPTION 'new proofing required'; END IF;
 FOR old_id IN SELECT credential FROM profiles WHERE person=p.person AND credential!=c.id ORDER BY credential LOOP
  PERFORM revoke_credential(old_id);
 END LOOP;
 UPDATE credentials SET state='ACTIVE',expires=least(now_epoch+proposal.hours*3600,p.document_expires),decision=proposal.decision WHERE id=c.id;
 UPDATE activation_proposals SET approved_by=session_user,approved_at=now_epoch WHERE id=proposal_id;
 INSERT INTO events(credential,kind,time) VALUES(c.id,'ACTIVATED',now_epoch);
 INSERT INTO operator_events(actor,kind,credential,proposal) VALUES(session_user,'ACTIVATED',c.id,proposal_id);
END $$;

-- Deliberate fail-closed restore: run before any service receives access to a restored registry.
CREATE FUNCTION revoke_all_after_restore() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
BEGIN
 LOCK TABLE credentials,requests,federation_requests,challenges IN ACCESS EXCLUSIVE MODE;
 INSERT INTO enrollment_quarantine VALUES(1,floor(extract(epoch FROM clock_timestamp()))::bigint+86400)
  ON CONFLICT(id) DO UPDATE SET until_epoch=greatest(enrollment_quarantine.until_epoch,excluded.until_epoch);
 UPDATE credentials SET state='REVOKED';
 UPDATE requests SET state='CANCELLED' WHERE state IN ('PENDING','APPROVED');
 UPDATE federation_requests SET state='CANCELLED' WHERE state IN ('PENDING','APPROVED');
 DELETE FROM challenges;
 UPDATE activation_proposals SET expires=0 WHERE approved_at IS NULL;
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
GRANT SELECT ON operator_events TO openid_auditor;
GRANT SELECT ON activation_proposals TO openid_requester,openid_approver,openid_auditor;
GRANT EXECUTE ON FUNCTION request_activation(text,text,integer) TO openid_requester;
GRANT EXECUTE ON FUNCTION approve_activation(text) TO openid_approver;
GRANT EXECUTE ON FUNCTION revoke_credential(text),revoke_all_after_restore() TO openid_revoker;
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
