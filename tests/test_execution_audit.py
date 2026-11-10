import copy
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from handoff_witness.core import EvidenceError, ZERO, digest, sign
from handoff_witness.execution import ApprovedBrowser, HTTPBroker
from handoff_witness.execution_audit import DOMAIN, ExecutionJournal, verify_execution
from test_approval import setup
from test_execution import operation, approve_operation


def audited(setup, *, status=200, failure=False):
    gate, _, _, _, binding = setup
    op = operation(binding)
    approval_id = approve_operation(setup, op)
    journal = ExecutionJournal(binding['session'])
    with patch('handoff_witness.execution.http.client.HTTPSConnection') as factory:
        connection = factory.return_value
        connection.getresponse.return_value.status = status
        connection.getresponse.return_value.read.return_value = b'OK'
        connection.getresponse.return_value.getheaders.return_value = [('Content-Type', 'text/plain')]
        if failure:
            connection.endheaders.side_effect = OSError('uncertain send')
            with pytest.raises(OSError):
                HTTPBroker(gate, journal=journal).dispatch(op, approval_id)
        else:
            HTTPBroker(gate, journal=journal).dispatch(op, approval_id)
    records, checkpoint = journal.snapshot()
    bundle = {'format': DOMAIN + '/bundle', 'records': records, 'approvals': [gate.approval_evidence(approval_id)]}
    return journal, bundle, checkpoint


def verify(setup, journal, bundle, checkpoint, **changes):
    gate, auth, key, *_ = setup
    anchors = dict(executor_key=journal.key.public_key(), gate_key=key.public_key(),
                   credential_id=auth.id, credential_public_key=auth.public, rp_id=gate.rp_id, origin=gate.origin)
    anchors.update(changes)
    return verify_execution(bundle, checkpoint, **anchors)


def reanchor(journal, bundle):
    """Test-only signer: make forged semantics cryptographically well formed."""
    previous = ZERO
    for seq, record in enumerate(bundle['records']):
        record['event'].update(seq=seq, previous=previous)
        record['signature'] = sign(journal.key, record['event'])
        previous = digest(record)
    body = {'domain': DOMAIN + '/checkpoint', 'session': journal.session,
            'count': len(bundle['records']), 'head': previous}
    return {'checkpoint': body, 'signature': sign(journal.key, body)}


def test_success_preserves_observation_and_intent_boundaries(setup):
    journal, bundle, checkpoint = audited(setup)
    result = verify(setup, journal, bundle, checkpoint)['requests'][0]
    assert result['approval'] == 'credential_verified'
    assert result['stage'] == 'relay_prepared'
    assert result['upstream_status'] == result['relay_status'] == 200
    assert result['relay_body_sha256'] == hashlib.sha256(b'OK').hexdigest()
    assert result['initiation'] == 'not_established'
    assert result['remote_execution'] == 'not_independently_established'


def test_redirect_distinguishes_upstream_from_local_response(setup):
    journal, bundle, checkpoint = audited(setup, status=302)
    result = verify(setup, journal, bundle, checkpoint)['requests'][0]
    assert (result['upstream_status'], result['relay_status']) == (302, 502)


def test_uncertain_failure_is_not_reported_as_no_execution(setup):
    journal, bundle, checkpoint = audited(setup, failure=True)
    result = verify(setup, journal, bundle, checkpoint)['requests'][0]
    assert result['stage'] == 'attempt_failed'
    assert result['remote_execution'] == 'not_independently_established'
    assert 'upstream_status' not in result


@pytest.mark.parametrize('change', ['url', 'response', 'delete', 'reorder', 'duplicate', 'truncate', 'approval', 'missing_approval', 'extra_approval', 'signature', 'checkpoint'])
def test_export_tampering_rejected(setup, change):
    journal, bundle, checkpoint = audited(setup)
    if change == 'url':
        bundle['records'][0]['event']['data']['receipt']['reservation']['binding']['url'] += '/changed'
    elif change == 'response':
        bundle['records'][-1]['event']['data']['status'] = 201
    elif change == 'delete':
        del bundle['records'][1]
    elif change == 'reorder':
        bundle['records'][1:3] = reversed(bundle['records'][1:3])
    elif change == 'duplicate':
        bundle['records'].append(copy.deepcopy(bundle['records'][-1]))
    elif change == 'truncate':
        bundle['records'].pop()
    elif change == 'approval':
        bundle['approvals'][0]['evidence']['challenge_document']['binding']['method'] = 'DELETE'
    elif change == 'missing_approval':
        bundle['approvals'].clear()
    elif change == 'extra_approval':
        bundle['approvals'].append(copy.deepcopy(bundle['approvals'][0]))
    elif change == 'signature':
        bundle['records'][0]['signature'] = 'invalid'
    elif change == 'checkpoint':
        checkpoint['checkpoint']['head'] = ZERO
    with pytest.raises(EvidenceError):
        verify(setup, journal, bundle, checkpoint)


@pytest.mark.parametrize('anchor', ['executor_key', 'gate_key', 'credential_id', 'credential_public_key', 'origin', 'rp_id'])
def test_wrong_trust_anchors_rejected(setup, anchor):
    journal, bundle, checkpoint = audited(setup)
    replacement = Ed25519PrivateKey.generate().public_key() if anchor.endswith('_key') and anchor != 'credential_public_key' else b'invalid' if anchor.startswith('credential') else 'wrong.example'
    with pytest.raises(EvidenceError):
        verify(setup, journal, bundle, checkpoint, **{anchor: replacement})


@pytest.mark.parametrize('change', ['no_reservation', 'double_reservation', 'headers_before_attempt', 'invalid_relay', 'double_terminal', 'unknown_field', 'other_session'])
def test_signed_invalid_lifecycle_rejected(setup, change):
    journal, bundle, _ = audited(setup)
    records = bundle['records']
    if change == 'no_reservation':
        records.pop(0)
    elif change == 'double_reservation':
        records.insert(1, copy.deepcopy(records[0]))
    elif change == 'headers_before_attempt':
        records.pop(1)
    elif change == 'invalid_relay':
        records[-1]['event']['data']['status'] = 204
    elif change == 'double_terminal':
        records.append(copy.deepcopy(records[-1]))
    elif change == 'unknown_field':
        records[1]['event']['data']['human_approved'] = True
    elif change == 'other_session':
        records[1]['event']['session'] = 'other'
    checkpoint = reanchor(journal, bundle)
    with pytest.raises(EvidenceError):
        verify(setup, journal, bundle, checkpoint)


@pytest.mark.parametrize('change', ['digest', 'binding', 'expired', 'predates_approval', 'gate_signature'])
def test_cross_artifact_links_rejected_even_with_executor_signature(setup, change):
    journal, bundle, _ = audited(setup)
    receipt = bundle['records'][0]['event']['data']['receipt']
    body = receipt['reservation']
    if change == 'digest':
        body['approval_sha256'] = ZERO
    elif change == 'binding':
        body['binding']['headers_sha256'] = 'f' * 64
    elif change == 'expired':
        body['reserved_at'] += 1000
    elif change == 'predates_approval':
        body['reserved_at'] -= 1
    if change != 'gate_signature':
        receipt['signature'] = sign(setup[2], body)
    else:
        receipt['signature'] = 'invalid'
    checkpoint = reanchor(journal, bundle)
    with pytest.raises(EvidenceError):
        verify(setup, journal, bundle, checkpoint)


def test_partial_history_reports_only_observed_stage(setup):
    journal, bundle, _ = audited(setup)
    bundle['records'] = bundle['records'][:1]
    checkpoint = reanchor(journal, bundle)
    result = verify(setup, journal, bundle, checkpoint)['requests'][0]
    assert result['stage'] == 'reserved'
    assert 'upstream_status' not in result
    assert result['remote_execution'] == 'not_independently_established'


def test_journal_failure_before_attempt_prevents_socket(setup):
    gate, _, _, _, binding = setup
    op = operation(binding)
    approval_id = approve_operation(setup, op)
    journal = ExecutionJournal(binding['session'])
    with patch.object(journal, 'append', side_effect=OSError('audit unavailable')):
        with patch('handoff_witness.execution.http.client.HTTPSConnection') as connection:
            with pytest.raises(OSError):
                HTTPBroker(gate, journal=journal).dispatch(op, approval_id)
            connection.assert_not_called()
    with pytest.raises(EvidenceError):
        gate.reserve(approval_id, op.binding())


def test_historical_export_after_revocation_and_expiry(setup, tmp_path):
    journal, bundle, checkpoint = audited(setup)
    gate, auth, _, now, _ = setup
    gate.revoke(auth.id)
    now[0] += 1000
    journal.save(tmp_path / 'audit', gate)
    saved = json.loads((tmp_path / 'audit/bundle.json').read_text())
    assert verify(setup, journal, saved, checkpoint)['request_count'] == 1


def test_concurrent_journal_chain_is_serialized(setup):
    gate, auth, _, _, binding = setup
    journal = ExecutionJournal(binding['session'])
    receipts, approvals = [], []
    for index in range(12):
        next_binding = {**binding, 'request_id': str(index)}
        options = gate.begin(next_binding, auth.id)
        approvals.append(gate.finish(options['approval_id'], auth.assertion(options, count=index + 1)))
        receipts.append(gate.reserve(options['approval_id'], next_binding))
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda receipt: journal.append('reserved', receipt=receipt), receipts))
    records, checkpoint = journal.snapshot()
    bundle = {'format': DOMAIN + '/bundle', 'records': records, 'approvals': approvals}
    assert verify(setup, journal, bundle, checkpoint)['request_count'] == 12


def test_export_before_executor_close_rejected(setup, tmp_path):
    async def deny(binding):
        return None
    executor = ApprovedBrowser(None, setup[0], deny, allowed_origins=['https://fixture.invalid'], approval_timeout=10)
    with pytest.raises(RuntimeError):
        executor.save_evidence(tmp_path / 'audit')


def test_expected_session_enforced(setup):
    journal, bundle, checkpoint = audited(setup)
    assert verify(setup, journal, bundle, checkpoint, expected_session=journal.session)['request_count'] == 1
    with pytest.raises(EvidenceError, match='expected session'):
        verify(setup, journal, bundle, checkpoint, expected_session='another-session')
