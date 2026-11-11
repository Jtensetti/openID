"""Disposable registry and operator accounts for the browser federation test."""
from contextlib import ExitStack
import os
from pathlib import Path
import secrets

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from postgres import PostgresWallet
from raft_test_support import RaftCluster
from transit import TransitVault
from postgres_continuity import PostgresContinuity
from test_continuity_support import REFERENCE,SyntheticContinuity


class FederationPostgres:
    def __init__(self, directory, origin, *, external_bao=None):
        self.resources = ExitStack()
        try:
            self.admin_dsn = os.environ['OPENID_TEST_POSTGRES']
            if external_bao is None:
                cluster = RaftCluster(Path(directory) / 'raft')
                self.resources.callback(cluster.close)
                node = cluster.start()
                token, _ = cluster.initialize(node)
                tokens = cluster.provision(node, token)
                certificate = str(cluster.cert)
            else:
                node = {'address': external_bao['address']}
                tokens, certificate = external_bao['tokens'], external_bao['ca']
            self.dsns = {}
            with psycopg.connect(self.admin_dsn, autocommit=True) as admin:
                admin.execute((Path(__file__).parents[1] / 'deployment/cluster/schema.sql').read_text(), prepare=False)
                for user, role in {'enroller': 'enroller', 'wallet': 'wallet', 'bridge': 'wallet', 'registry': 'registry', 'requester': 'requester', 'approver': 'approver', 'contact':'contact', 'continuity':'continuity'}.items():
                    name, password = 'federation_' + user, secrets.token_urlsafe(32)
                    admin.execute(sql.SQL('CREATE ROLE {} LOGIN PASSWORD {}').format(sql.Identifier(name), sql.Literal(password)))
                    admin.execute(sql.SQL('GRANT {} TO {}').format(sql.Identifier('openid_' + role), sql.Identifier(name)))
                    self.dsns[user] = make_conninfo(**(conninfo_to_dict(self.admin_dsn) | {'user': name, 'password': password}))
                admin.execute('INSERT INTO openid.continuity_config VALUES(1,%s)',(REFERENCE,))
            self.synthetic=SyntheticContinuity()
            self.controller=PostgresContinuity(self.dsns['continuity'],self.synthetic.authority)
            self.resources.callback(self.controller.close)
            def wallet(role):
                vault = TransitVault(node['address'], tokens[role], certificate)
                result = PostgresWallet(self.dsns[role], origin, vault,revocation=self.controller)
                self.resources.callback(result.close)
                return result
            self.enroller = wallet('enroller')
            self.wallet = wallet('wallet')
            self.registry = wallet('registry')
            self.contact = wallet('contact')
            self.bridge_wallet = wallet('wallet')
        except BaseException:
            self.resources.close()
            raise

    def activate(self, credential):
        from registry_binding import RegistryBindings, RegistryResult
        from test_identity import TEST_PERSON_NUMBER
        def lookup(query):
            now = int(self.registry.clock())
            return RegistryResult(query.nonce, query.credential, query.profile_version,
                query.document_reference, 'PROOF-'+query.nonce, now, now+3600,
                'MATCH', False, 'personnummer', TEST_PERSON_NUMBER)
        from continuity_operator import prepare
        prepare(self.contact,credential,'synthetic@example.invalid','SYNTHETIC_CONTACT_REVIEW',
                self.synthetic,'ledger','contacts')
        RegistryBindings(self.registry, source='fixture-registry', lookup=lookup).bind(credential)
        with psycopg.connect(self.dsns['requester']) as operator:
            proposal = operator.execute('SELECT openid.request_activation(%s,%s,%s)',
                                        (credential, 'TEST-federation-001', 24)).fetchone()[0]
        with psycopg.connect(self.dsns['approver']) as operator:
            intent=operator.execute('SELECT openid.approve_activation(%s)', (proposal,)).fetchone()[0]
        self.controller.complete(intent)

    def expire_pending(self):
        with psycopg.connect(self.admin_dsn) as admin:
            admin.execute("UPDATE openid.federation_requests SET expires=0 WHERE state='PENDING'")

    def close(self):
        self.resources.close()
