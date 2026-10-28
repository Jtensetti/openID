-- Stop writers and verify a schema-3 backup with its pinned tools first.
BEGIN;
SET LOCAL ROLE openid_owner;
SET LOCAL search_path=openid,pg_catalog;
LOCK TABLE schema_version IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF (SELECT array_agg(version) FROM schema_version) IS DISTINCT FROM ARRAY[3] THEN
  RAISE EXCEPTION 'schema version 3 required';
 END IF;
END $$;
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
ALTER TABLE schema_version DROP CONSTRAINT schema_version_version_check;
UPDATE schema_version SET version=4;
ALTER TABLE schema_version ADD CONSTRAINT schema_version_version_check CHECK(version=4);
COMMIT;
