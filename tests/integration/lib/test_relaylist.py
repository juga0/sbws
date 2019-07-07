import datetime

from sbws.lib.relaylist import Relay


def test_relay_properties(persistent_launch_tor):
    cont = persistent_launch_tor
    # AA45C13025C037F056E734169891878ED0880231 is auth1
    fp = 'AA45C13025C037F056E734169891878ED0880231'
    relay = Relay(fp, cont)
    assert relay.nickname == 'auth1'
    assert relay.fingerprint == 'AA45C13025C037F056E734169891878ED0880231'
    assert 'Authority' in relay.flags
    assert not relay.exit_policy or not relay.exit_policy.is_exiting_allowed()
    assert relay.average_bandwidth == 1073741824
    assert relay.consensus_bandwidth == 0
    assert relay.address == '127.10.0.1'
    assert relay.master_key_ed25519 == \
        'wLglSEw9/DHfpNrlrqjVRSnGLVWfnm0vYxkryH4aT6Q'


def test_relay_list_last_consensus_timestamp(rl):
    assert rl.last_consensus_timestamp == \
        rl._relays[0].last_consensus_timestamp


def test_relay_list_add_consensus_timestamp_not_initialized(rl):
    # Obtain a relay
    relay = [r for r in rl.relays
             if r.nickname == 'relay1mbyteMAB'][0]
    # Obtain the last consensus timestamp from the relay
    timestamp = relay.last_consensus_timestamp
    # Fake that the list is None
    relay._consensus_timestamps = None
    # Add the consensus timestamp passing the argument
    relay._add_consensus_timestamp(timestamp)
    assert relay.last_consensus_timestamp == timestamp
    # Fake that the list is empty
    relay._consensus_timestamps = []
    # Add the consensus timestamp
    relay._add_consensus_timestamp(timestamp)
    assert relay.last_consensus_timestamp == timestamp


def test_relay_list_add_consensus_timestamp_no_timestamp(rl):
    # Obtain a relay
    relay = [r for r in rl.relays
             if r.nickname == 'relay1mbyteMAB'][0]
    # Add a consensus timestamp without timestamp argument
    relay._add_consensus_timestamp()
    # The last timestamp migth not be like the original one, but there will be
    # one
    assert relay.last_consensus_timestamp


def test_relay_list_add_consensus_timestamp_older(rl):
    # Obtain a relay
    relay = [r for r in rl.relays
             if r.nickname == 'relay1mbyteMAB'][0]
    # Obtain the last consensus timestamp from the relay
    last_consensus_timestamp = relay.last_consensus_timestamp
    # Create a timestamp that is a day older
    timestamp = last_consensus_timestamp - datetime.timedelta(days=1)
    # Add the old consensus timestamp
    relay._add_consensus_timestamp(timestamp)
    # The last consensus timestamp is not the added timestamp cause it's in the
    # past
    assert relay.last_consensus_timestamp == last_consensus_timestamp
