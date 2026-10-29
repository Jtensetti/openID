-- Stop applications and maintenance; verify a schema-4 backup with its pinned tools.
BEGIN;
SET LOCAL ROLE openid_owner;
SET LOCAL search_path=openid,pg_catalog;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
LOCK TABLE schema_version IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF (SELECT array_agg(version) FROM schema_version) IS DISTINCT FROM ARRAY[4] THEN
  RAISE EXCEPTION 'schema version 4 required';
 END IF;
END $$;
LOCK TABLE federation_requests IN ACCESS EXCLUSIVE MODE;
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
  ORDER BY p.id LIMIT max_batch FOR UPDATE OF p SKIP LOCKED);
 GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
 DELETE FROM biometric_attempts WHERE document_tag IN (SELECT document_tag FROM biometric_attempts
  WHERE times[cardinality(times)]<=now_epoch-86400 ORDER BY document_tag LIMIT max_batch FOR UPDATE SKIP LOCKED);
 GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
 INSERT INTO maintenance_runs VALUES(1,clock_timestamp(),removed)
  ON CONFLICT(id) DO UPDATE SET completed_at=excluded.completed_at,removed=excluded.removed;
 RETURN removed;
END $$;

REVOKE ALL ON FUNCTION purge_expired(integer,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION purge_expired(integer,integer,integer) TO openid_maintenance;
ALTER TABLE schema_version DROP CONSTRAINT schema_version_version_check;
UPDATE schema_version SET version=5;
ALTER TABLE schema_version ADD CONSTRAINT schema_version_version_check CHECK(version=5);
COMMIT;
