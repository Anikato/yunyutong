from datetime import datetime, timezone

from sqlalchemy import select, update

from app.extensions import db
from app.models import DnsRecord, Domain


def sync_domains(token, provider):
    zones = provider.get_zones()
    existing = {domain.zone_id: domain for domain in token.domains}
    fetched_at = datetime.now(timezone.utc)

    for zone in zones:
        if not zone['id']:
            raise ValueError('DNS response contains a domain without an ID')
        zone_id = str(zone['id'])
        domain = existing.get(zone_id)
        if domain is None:
            domain = Domain(zone_id=zone_id, api_token=token)
            db.session.add(domain)
            existing[zone_id] = domain
        domain.name = zone['name']
        domain.status = zone.get('status')
        domain.fetched_at = fetched_at

    db.session.commit()


def advance_record_cache(domain_id, version=None):
    statement = update(Domain).where(Domain.id == domain_id)
    if version is not None:
        statement = statement.where(Domain.dns_sync_version == version)
    result = db.session.execute(
        statement.values(dns_sync_version=Domain.dns_sync_version + 1)
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        raise RuntimeError('DNS cache changed during refresh')


def sync_records(domain, provider):
    version = db.session.execute(
        select(Domain.dns_sync_version).where(Domain.id == domain.id)
    ).scalar_one()
    records = provider.get_dns_records(domain.zone_id)
    # Claim the cache revision after the network request so an older snapshot cannot overwrite a newer one.
    advance_record_cache(domain.id, version)
    cached_records = DnsRecord.query.filter_by(domain_id=domain.id).populate_existing()
    existing = {record.record_id: record for record in cached_records}
    seen = set()

    for item in records:
        if not item['id']:
            raise ValueError('DNS response contains a record without an ID')
        record_id = str(item['id'])
        if record_id in seen:
            raise ValueError('DNS response contains a duplicate record ID')
        seen.add(record_id)
        record = existing.pop(record_id, None)
        if record is None:
            record = DnsRecord(record_id=record_id, domain=domain)
            db.session.add(record)
        record.type = item['type']
        record.name = item['name']
        record.content = item['content']
        record.ttl = item.get('ttl')
        record.proxied = item.get('proxied', False)
        record.priority = item.get('priority')

    for record in existing.values():
        db.session.delete(record)

    db.session.commit()
