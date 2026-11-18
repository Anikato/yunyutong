import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.fernet import Fernet
from flask import g

with patch.dict(os.environ, {'ENCRYPTION_KEY': Fernet.generate_key().decode()}):
    from app import create_app
    from app.extensions import db
    from app.models import ApiToken, DnsRecord, Domain, User
    from app.providers.aliyun import AliyunProvider
    from app.providers.base import DNSProvider
    from app.providers.cloudflare import CloudflareProvider
    from config import TestingConfig


class FakeProvider(DNSProvider):
    def __init__(self):
        self.records = [
            {'id': 'remote-record', 'type': 'A', 'name': 'www.example.test',
             'content': '192.0.2.1', 'ttl': 600},
        ]
        self.reads = []
        self.error = None

    def _validate_credentials(self):
        pass

    def get_credential_fields(self):
        return []

    def verify_credentials(self):
        return True

    def get_zones(self):
        self.reads.append('zones')
        return [{'id': 'example.test', 'name': 'example.test', 'status': 'active'}]

    def get_dns_records(self, zone_id):
        self.reads.append(zone_id)
        if self.error:
            raise self.error
        return self.records

    def create_dns_record(self, zone_id, record_data):
        self.records = [*self.records, {'id': 'created', **record_data}]
        return True, {}

    def update_dns_record(self, zone_id, record_id, record_data):
        self.records = [
            {'id': record_id, **record_data} if record['id'] == record_id else record
            for record in self.records
        ]
        return True, {}

    def delete_dns_record(self, zone_id, record_id):
        self.records = [item for item in self.records if item['id'] != record_id]
        return True, ''


class DnsTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestingConfig)
        self.context = self.app.app_context()
        self.context.push()
        self.addCleanup(self.context.pop)
        db.create_all()
        self.client = self.app.test_client()
        self.provider = FakeProvider()
        provider = patch.object(ApiToken, 'get_provider', return_value=self.provider)
        provider.start()
        self.addCleanup(provider.stop)
        self.accounts = []
        for username in ('alice', 'bob'):
            user = User(username=username, password_hash='unused')
            token = ApiToken(owner=user, name=username, provider_type='aliyun', status='valid')
            token.set_credentials({'test': True})
            db.session.add(token)
            db.session.commit()
            self.accounts.append((user.id, token.id))

    def login(self, index=0):
        user_id, token_id = self.accounts[index]
        g.pop('_login_user', None)
        with self.client.session_transaction() as session:
            session['_user_id'] = str(user_id)
        return token_id

    def sync_domains(self, token_id):
        response = self.client.post(f'/token/{token_id}/domains')
        self.assertEqual(response.status_code, 302)
        return Domain.query.filter_by(api_token_id=token_id).one()

    def sync_records(self, domain_id):
        return self.client.post(f'/domains/{domain_id}/dns/sync')

    def test_sync_keeps_identical_external_ids_in_each_accounts_cache(self):
        first = self.sync_domains(self.login(0))
        self.assertEqual(self.sync_records(first.id).status_code, 302)
        first_record = DnsRecord.query.filter_by(domain_id=first.id).one()

        second = self.sync_domains(self.login(1))
        self.assertEqual(self.sync_records(second.id).status_code, 302)
        second_record = DnsRecord.query.filter_by(domain_id=second.id).one()

        self.assertNotEqual(first.id, second.id)
        self.assertNotEqual(first_record.id, second_record.id)
        self.assertEqual(first.api_token_id, self.accounts[0][1])
        self.assertEqual(first_record.domain_id, first.id)
        self.assertIn(b'www.example.test', self.client.get('/?q=www').data)
        self.assertEqual(self.client.get(f'/domains/{second.id}/dns').status_code, 200)
        self.assertEqual(self.client.get('/zone/example.test/dns').status_code, 200)
        self.assertEqual(self.client.get(f'/domains/{first.id}/dns').status_code, 404)
        self.assertEqual(self.client.get(f'/records/{first_record.id}/edit').status_code, 404)

    def test_browsing_only_reads_cached_data(self):
        token_id = self.login()
        domain = self.sync_domains(token_id)
        self.assertEqual(self.sync_records(domain.id).status_code, 302)
        self.provider.reads.clear()

        self.assertIn(b'example.test', self.client.get(f'/token/{token_id}/domains').data)
        response = self.client.get(f'/domains/{domain.id}/dns?q=192.0.2.1&page=1')
        self.assertIn(b'www.example.test', response.data)
        self.assertEqual(self.provider.reads, [])

    def test_failed_refresh_preserves_cache_but_successful_empty_refresh_clears_it(self):
        domain = self.sync_domains(self.login())
        self.assertEqual(self.sync_records(domain.id).status_code, 302)
        self.provider.error = RuntimeError('provider temporarily unavailable')
        self.assertEqual(self.sync_records(domain.id).status_code, 302)
        self.assertEqual(DnsRecord.query.count(), 1)

        self.provider.error = None
        self.provider.records = []
        self.assertEqual(self.sync_records(domain.id).status_code, 302)
        self.assertEqual(DnsRecord.query.count(), 0)

    def test_record_create_updates_home_search_without_a_followup_get(self):
        domain = self.sync_domains(self.login())
        response = self.client.post(f'/domains/{domain.id}/dns', data={
            'record_type': 'A', 'name': 'new.example.test', 'content': '192.0.2.2', 'ttl': '600',
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn(b'new.example.test', self.client.get('/?q=192.0.2.2').data)

    def test_record_edit_and_delete_update_home_search(self):
        domain = self.sync_domains(self.login())
        self.assertEqual(self.sync_records(domain.id).status_code, 302)
        record_id = DnsRecord.query.one().id
        response = self.client.post(f'/records/{record_id}/edit', data={
            'record_type': 'A', 'name': 'www.example.test', 'content': '192.0.2.3', 'ttl': '600',
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn(b'www.example.test', self.client.get('/?q=192.0.2.3').data)
        self.assertEqual(self.client.post(f'/records/{record_id}/delete').status_code, 302)
        self.assertEqual(DnsRecord.query.count(), 0)

    def test_edit_returns_to_the_search_that_opened_it(self):
        domain = self.sync_domains(self.login())
        self.assertEqual(self.sync_records(domain.id).status_code, 302)
        record_id = DnsRecord.query.one().id
        response = self.client.post(f'/records/{record_id}/edit?source=search&q=www&sort=name', data={
            'record_type': 'A', 'name': 'www.example.test', 'content': '192.0.2.3', 'ttl': '600',
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, '/index?q=www&sort=name')

    def test_delayed_snapshot_does_not_overwrite_a_newer_refresh(self):
        domain = self.sync_domains(self.login())
        domain_id = domain.id
        older = self.provider.records

        def fetch_records(zone_id):
            self.provider.records = [{**older[0], 'content': '192.0.2.9'}]
            with self.app.app_context(), patch.object(
                self.provider, 'get_dns_records', return_value=self.provider.records,
            ):
                self.assertEqual(self.sync_records(domain_id).status_code, 302)
            return older

        with patch.object(self.provider, 'get_dns_records', side_effect=fetch_records):
            self.assertEqual(self.sync_records(domain_id).status_code, 302)
        self.assertEqual(DnsRecord.query.one().content, '192.0.2.9')

    def test_domain_refresh_leaves_no_cache_for_a_concurrently_removed_token(self):
        token_id = self.login()
        zones = self.provider.get_zones()

        def fetch_zones():
            with self.app.app_context():
                db.session.delete(db.session.get(ApiToken, token_id))
                db.session.commit()
            return zones

        with patch.object(self.provider, 'get_zones', side_effect=fetch_zones):
            self.assertEqual(self.client.post(f'/token/{token_id}/domains').status_code, 302)
        self.assertEqual(Domain.query.count(), 0)


class ProviderTests(unittest.TestCase):
    def test_cloudflare_record_listing_distinguishes_empty_snapshot_from_failure(self):
        provider = CloudflareProvider({'api_token': 'test'})
        with patch('app.providers.cloudflare.requests.get') as get:
            get.return_value.status_code = 200
            get.return_value.json.return_value = {'success': True, 'result': []}
            self.assertEqual(provider.get_dns_records('zone'), [])
            get.return_value.json.return_value['result_info'] = {'total_pages': 1, 'total_count': 1}
            with self.assertRaises(RuntimeError):
                provider.get_dns_records('zone')
            get.return_value.status_code = 503
            with self.assertRaises(RuntimeError):
                provider.get_dns_records('zone')

    def test_aliyun_record_listing_distinguishes_empty_snapshot_from_failure(self):
        provider = AliyunProvider({'access_key_id': 'test', 'access_key_secret': 'test'})
        empty = SimpleNamespace(total_count=0, domain_records=None)
        with patch.object(provider, '_get_client') as get_client:
            request = get_client.return_value.describe_domain_records_with_options
            request.return_value = SimpleNamespace(status_code=200, body=empty)
            self.assertEqual(provider.get_dns_records('example.test'), [])
            request.return_value.status_code = 503
            with self.assertRaises(RuntimeError):
                provider.get_dns_records('example.test')


if __name__ == '__main__':
    unittest.main()
