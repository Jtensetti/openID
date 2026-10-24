-- Stop all application/maintenance writers first. Use the controlled database owner.
-- Take and verify a v1 backup using the previous, pinned application revision first.
BEGIN;
SET LOCAL ROLE openid_owner;
SET LOCAL search_path=openid,pg_catalog;
LOCK TABLE schema_version IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF (SELECT array_agg(version) FROM schema_version) IS DISTINCT FROM ARRAY[1] THEN
  RAISE EXCEPTION 'schema version 1 required';
 END IF;
END $$;
CREATE TABLE biometric_attempts(document_tag text PRIMARY KEY, times bigint[] NOT NULL
 CHECK(cardinality(times) BETWEEN 1 AND 5 AND array_position(times,NULL) IS NULL));

CREATE OR REPLACE FUNCTION reserve_biometric_attempt(tag text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,openid,pg_temp AS $$
DECLARE recent bigint[]; now_epoch bigint:=floor(extract(epoch FROM clock_timestamp()))::bigint;
BEGIN
 IF tag IS NULL OR length(tag) NOT BETWEEN 32 AND 256 OR tag !~ '^[A-Za-z0-9_:/+=-]+$' THEN RAISE EXCEPTION 'document tag required'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(tag,7833));
 SELECT coalesce(array_agg(t ORDER BY t),'{}'::bigint[]) INTO recent
  FROM biometric_attempts b CROSS JOIN LATERAL unnest(b.times) t
  WHERE b.document_tag=tag AND t>now_epoch-86400;
 IF cardinality(recent)>=5 THEN RETURN -1; END IF;
 INSERT INTO biometric_attempts VALUES(tag,array_append(recent,now_epoch))
  ON CONFLICT(document_tag) DO UPDATE SET times=excluded.times;
 RETURN 4-cardinality(recent);
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
 FOR item IN SELECT * FROM (VALUES
  ('challenges','expires',now_epoch),('requests','expires',now_epoch-3600),
  ('federation_requests','expires',now_epoch-3600)) AS t(table_name,column_name,cutoff)
 LOOP
  EXECUTE format('DELETE FROM %I WHERE id IN (SELECT id FROM %I WHERE %I<$1 ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED)',
   item.table_name,item.table_name,item.column_name) USING item.cutoff,max_batch;
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
REVOKE ALL ON FUNCTION reserve_biometric_attempt(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION reserve_biometric_attempt(text) TO openid_enroller;
GRANT SELECT ON biometric_attempts TO openid_backup;
ALTER TABLE schema_version DROP CONSTRAINT schema_version_version_check;
UPDATE schema_version SET version=2;
ALTER TABLE schema_version ADD CONSTRAINT schema_version_version_check CHECK(version=2);
COMMIT;
