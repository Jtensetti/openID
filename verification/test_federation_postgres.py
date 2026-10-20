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


class FederationPostgres:
    def __init__(self, directory, origin):
        self.resources = ExitStack()
        try:
            self.admin_dsn = os.environ['OPENID_TEST_POSTGRES']
            cluster = RaftCluster(Path(directory) / 'raft')
            self.resources.callback(cluster.close)
            node = cluster.start()
            token, _ = cluster.initialize(node)
            tokens = cluster.provision(node, token)
            self.dsns = {}
            with psycopg.connect(self.admin_dsn, autocommit=True) as admin:
                admin.execute((Path(__file__).parents[1] / 'deployment/cluster/schema.sql').read_text(), prepare=False)
                for user, role in {'enroller': 'enroller', 'wallet': 'wallet', 'requester': 'requester', 'approver': 'approver'}.items():
                    name, password = 'federation_' + user, secrets.token_urlsafe(32)
                    admin.execute(sql.SQL('CREATE ROLE {} LOGIN PASSWORD {}').format(sql.Identifier(name), sql.Literal(password)))
                    admin.execute(sql.SQL('GRANT {} TO {}').format(sql.Identifier('openid_' + role), sql.Identifier(name)))
                    self.dsns[user] = make_conninfo(**(conninfo_to_dict(self.admin_dsn) | {'user': name, 'password': password}))
            def wallet(role):
                vault = TransitVault(node['address'], tokens[role], str(cluster.cert))
                result = PostgresWallet(self.dsns[role], origin, vault)
                self.resources.callback(result.close)
                return result
            self.enroller = wallet('enroller')
            self.wallet = wallet('wallet')
            self.bridge_wallet = wallet('wallet')
        except BaseException:
            self.resources.close()
            raise

    def activate(self, credential):
        with psycopg.connect(self.dsns['requester']) as operator:
            proposal = operator.execute('SELECT openid.request_activation(%s,%s,%s)',
                                        (credential, 'TEST-federation-001', 24)).fetchone()[0]
        with psycopg.connect(self.dsns['approver']) as operator:
            operator.execute('SELECT openid.approve_activation(%s)', (proposal,))

    def expire_pending(self):
        with psycopg.connect(self.admin_dsn) as admin:
            admin.execute("UPDATE openid.federation_requests SET expires=0 WHERE state='PENDING'")

    def close(self):
        self.resources.close()
