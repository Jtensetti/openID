"""Prepare a separately reviewed contact and revocation proof; never activate.

Run using a separate operator IAM identity. The application's instance role
must not have these DynamoDB provisioning permissions. Email comes from stdin.
"""
import argparse
import hashlib
import json
import re
import secrets
import sys
from notices import bind_contact, reference
from revocation import configured_wallet
from wallet import identifier


def prepare(wallet, credential, recipient, evidence, client, ledger, contacts):
    identifier(credential); reference(evidence)
    if not wallet.notifications or wallet.revocation is None: raise ValueError('continuity required')
    if not isinstance(recipient, str) or not re.fullmatch(r'[^\s@<>]{1,64}@[^\s@<>]{1,189}', recipient):
        raise ValueError('email address')
    # Persist the encrypted proof before any remote write so a retry uses the
    # same proof. Different AAD prevents swapping an identity profile for it.
    with wallet.transaction() as db:
        row = wallet.credential(db, credential)
        if row['state'] not in {'PENDING_REVIEW', 'ACTIVE'}: raise ValueError('new registration required')
        if not db.execute('SELECT 1 FROM profiles WHERE credential=?', (credential,)).fetchone():
            raise ValueError('verified passport profile required')
        staged = db.execute('SELECT * FROM revocation_codes WHERE credential=?', (credential,)).fetchone()
        if staged is None:
            version = secrets.token_hex(24)
            value = {'token': secrets.token_urlsafe(32)}
            sealed = wallet.vault.crypt('seal', credential, 'revocation-token-v1', value)
            db.execute('INSERT INTO revocation_codes VALUES(?,?,?,?)',
                (credential, json.dumps(sealed), version, evidence))
        else:
            if staged['evidence'] != evidence: raise ValueError('contact review changed')
            version = staged['contact_version']
            value = wallet.vault.crypt('open', credential, 'revocation-token-v1', json.loads(staged['sealed']))
    digest = hashlib.sha256(value['token'].encode('ascii')).hexdigest()
    credential_item = {'credential': {'S': credential}, 'state': {'S': 'ENABLED'}, 'token_hash': {'S': digest}}
    contact_item = {'id': {'S': 'contact#'+version}, 'recipient': {'S': recipient},
                    'verified': {'BOOL': True}, 'evidence': {'S': evidence}}
    try:
        client.transact_write_items(TransactItems=[
            {'Put': {'TableName': ledger, 'Item': credential_item, 'ConditionExpression': 'attribute_not_exists(credential)'}},
            {'Put': {'TableName': contacts, 'Item': contact_item, 'ConditionExpression': 'attribute_not_exists(id)'}}])
    except Exception:
        # Resolve ambiguous commits without overwriting any remote state. A
        # tombstone, changed contact or missing half always blocks activation.
        current = client.get_item(TableName=ledger, Key={'credential': {'S': credential}}, ConsistentRead=True).get('Item')
        contact = client.get_item(TableName=contacts, Key={'id': {'S': 'contact#'+version}}, ConsistentRead=True).get('Item')
        if current != credential_item or contact != contact_item:
            raise ValueError('contact provisioning not confirmed') from None
    with wallet.transaction() as db:
        current = db.execute('SELECT * FROM notice_contacts WHERE credential=?', (credential,)).fetchone()
        if current is None: bind_contact(db, credential, version, evidence)
        elif current['contact_version'] != version or current['evidence'] != evidence:
            raise ValueError('immutable contact binding differs')
    return {'prepared': True, 'activationRequired': row['state'] == 'PENDING_REVIEW'}


def main():
    import boto3
    from botocore.config import Config
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', required=True)
    parser.add_argument('--credential', required=True)
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--ledger', required=True)
    parser.add_argument('--contacts', required=True)
    parser.add_argument('--independently-verified-contact', action='store_true', required=True)
    args = parser.parse_args()
    recipient = sys.stdin.readline(256).strip()
    wallet = configured_wallet(args.db, 'continuity-operator')
    config = Config(connect_timeout=2, read_timeout=5, retries={'total_max_attempts': 1})
    client = boto3.client('dynamodb', region_name='eu-north-1', config=config)
    try:
        result = prepare(wallet, args.credential, recipient, args.evidence, client, args.ledger, args.contacts)
        print(json.dumps(result))
    except Exception:
        print('Contact preparation not confirmed. No ID was activated.', file=sys.stderr)
        raise SystemExit(2)


if __name__ == '__main__': main()
