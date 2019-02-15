from datetime import datetime, timedelta

from stem.descriptor.router_status_entry import RouterStatusEntryV3
from stem.descriptor.server_descriptor import ServerDescriptor
from stem import Flag, DescriptorUnavailable, ControllerError
import random
import logging
from threading import Lock

from ..globals import MEASUREMENTS_PERIOD

log = logging.getLogger(__name__)


class Relay:
    def __init__(self, fp, cont, ns=None, desc=None):
        '''
        Given a relay fingerprint, fetch all the information about a relay that
        sbws currently needs and store it in this class. Acts as an abstraction
        to hide the confusion that is Tor consensus/descriptor stuff.

        :param str fp: fingerprint of the relay.
        :param cont: active and valid stem Tor controller connection
        '''
        assert isinstance(fp, str)
        assert len(fp) == 40
        if ns is not None:
            assert isinstance(ns, RouterStatusEntryV3)
            self._ns = ns
        else:
            try:
                self._ns = cont.get_network_status(fp, default=None)
            except (DescriptorUnavailable, ControllerError) as e:
                log.exception("Exception trying to get ns %s", e)
                self._ns = None
        if desc is not None:
            assert isinstance(desc, ServerDescriptor)
            self._desc = desc
        else:
            try:
                self._desc = cont.get_server_descriptor(fp, default=None)
            except (DescriptorUnavailable, ControllerError) as e:
                log.exception("Exception trying to get desc %s", e)
        self._consensus_timestamps = []

    def _from_desc(self, attr):
        if not self._desc:
            return None
        return getattr(self._desc, attr, None)

    def _from_ns(self, attr):
        if not self._ns:
            return None
        return getattr(self._ns, attr, None)

    @property
    def nickname(self):
        return self._from_ns('nickname')

    @property
    def fingerprint(self):
        return self._from_ns('fingerprint')

    @property
    def flags(self):
        return self._from_ns('flags')

    @property
    def exit_policy(self):
        return self._from_desc('exit_policy')

    @property
    def average_bandwidth(self):
        return self._from_desc('average_bandwidth')

    @property
    def burst_bandwidth(self):
        return self._from_desc('burst_bandwidth')

    @property
    def observed_bandwidth(self):
        return self._from_desc('observed_bandwidth')

    @property
    def consensus_bandwidth(self):
        return self._from_ns('bandwidth')

    @property
    def consensus_bandwidth_is_unmeasured(self):
        # measured appears only votes, unmeasured appears in consensus
        # therefore is_unmeasured is needed to know whether the bandwidth
        # value in consensus is comming from bwauth measurements or not.
        return self._from_ns('is_unmeasured')

    @property
    def address(self):
        return self._from_ns('address')

    @property
    def master_key_ed25519(self):
        """Obtain ed25519 master key of the relay in server descriptors.

        :returns: str, the ed25519 master key base 64 encoded without
                  trailing '='s.

        """
        # Even if this key is called master-key-ed25519 in dir-spec.txt,
        # it seems that stem parses it as ed25519_master_key
        key = self._from_desc('ed25519_master_key')
        if key is None:
            return None
        return key.rstrip('=')

    @property
    def consensus_valid_after(self):
        network_status_document = self._from_ns('document')
        if network_status_document:
            return getattr(network_status_document, 'valid_after', None)
        return None

    @property
    def last_consensus(self):
        return self._consensus_timestamps[-1]

    def set_consensus_timestamps(self, previous_timestamps, last_timestamp):
        self._consensus_timestamps = previous_timestamps
        self._consensus_timestamps.append(last_timestamp)

    def can_exit_to_port(self, port):
        """
        Returns True if the relay has an exit policy and the policy accepts
        exiting to the given portself or False otherwise.
        """
        assert isinstance(port, int)
        # if dind't get the descriptor, there isn't exit policy
        if not self.exit_policy:
            return False
        return self.exit_policy.can_exit_to(port=port)

    def is_exit_not_bad_allowing_port(self, port):
        return (Flag.BADEXIT not in self.flags and
                Flag.EXIT in self.flags and
                self.can_exit_to_port(port))


class RelayList:
    ''' Keeps a list of all relays in the current Tor network and updates it
    transparently in the background. Provides useful interfaces for getting
    only relays of a certain type.
    '''

    def __init__(self, args, conf, controller,
                 measurements_period=MEASUREMENTS_PERIOD):
        self._controller = controller
        self.rng = random.SystemRandom()
        self._refresh_lock = Lock()
        # To track all the consensus seen.
        self._consensus_timestamps = []
        # Initialize so that there's no error trying to access to it.
        # In future refactor, change to a dictionary, where the keys are
        # the relays' fingerprint.
        self._relays = []
        self._measurements_period = measurements_period
        self._refresh()

    def _need_refresh(self):
        # New consensuses happen every hour.
        return datetime.utcnow() >= \
            self.last_consensus + timedelta(seconds=60*60)

    @property
    def last_consensus(self):
        """Returns the datetime when the last consensus was obtained."""
        if (getattr(self, "_consensus_timestamps")
                and self._consensus_timestamps):
            return self._consensus_timestamps[-1]
        # If the object was not created from __init__, it won't have
        # consensus_timestamps attribute or it might be empty.
        # In this case force new update.
        # Anytime more than 1h in the past will be old.
        self._consensus_timestamps = []
        return datetime.utcnow() - timedelta(seconds=60*61)

    @property
    def relays(self):
        # See if we can get the list of relays without having to do a refresh,
        # which is expensive and blocks other threads
        if self._need_refresh():
            log.debug('We need to refresh our list of relays. '
                      'Going to wait for lock.')
            # Whelp we couldn't just get the list of relays because the list is
            # stale. Wait for the lock so we can refresh it.
            with self._refresh_lock:
                log.debug('We got the lock. Now to see if we still '
                          'need to refresh.')
                # Now we have the lock ... but wait! Maybe someone else already
                # did the refreshing. So check if it still needs refreshing. If
                # not, we can do nothing.
                if self._need_refresh():
                    log.debug('Yup we need to refresh our relays. Doing so.')
                    self._refresh()
                else:
                    log.debug('No we don\'t need to refresh our relays. '
                              'It was done by someone else.')
            log.debug('Giving back the lock for refreshing relays.')
        return self._relays

    @property
    def fast(self):
        return self._relays_with_flag(Flag.FAST)

    @property
    def exits(self):
        return self._relays_with_flag(Flag.EXIT)

    @property
    def bad_exits(self):
        return self._relays_with_flag(Flag.BADEXIT)

    @property
    def non_exits(self):
        return self._relays_without_flag(Flag.EXIT)

    @property
    def guards(self):
        return self._relays_with_flag(Flag.GUARD)

    @property
    def authorities(self):
        return self._relays_with_flag(Flag.AUTHORITY)

    def random_relay(self):
        return self.rng.choice(self.relays)

    def _relays_with_flag(self, flag):
        return [r for r in self.relays if flag in r.flags]

    def _relays_without_flag(self, flag):
        return [r for r in self.relays if flag not in r.flags]

    def _init_relays(self):
        c = self._controller
        try:
            relays = [Relay(ns.fingerprint, c, ns=ns)
                      for ns in c.get_network_statuses()]
        except ControllerError as e:
            log.exception("Exception trying to init relays %s", e)
            return []
        return relays

    def remove_old_consensus_timestamps(self, consensus_timestamps):
        oldest_date = datetime.utcnow() - timedelta(self._measurements_period)
        [consensus_timestamps.remove(i)
         for i, t in enumerate(consensus_timestamps) if t < oldest_date]

    @property
    def _remove_old_consensus_timestamps(self):
        self.remove_old_consensus_timestamps(self._consensus_timestamps)

    @property
    def _update_consensus_timestamps(self):
        # The relays' network status document V3 should have the consensus
        # ``valid_after`` attribute that can be used as the date of the last
        # consensus seen.
        # Try with several relays in case one fail.
        for relay in self._relays:
            if relay.consensus_valid_after is not None:
                self._consensus_timestamps.append(relay.consensus_valid_after)
                log.info("Updated relays from valid after consensus: %s",
                         relay.consensus_valid_after)
            return
        log.warning("Could not find date of the last consensus.")
        # Assuming it was just now:
        self._consensus_timestamps.append(datetime.utcnow())

    @property
    def _obtain_relays_previous_consensus_timestamps(self):
        return dict([(r.fingerprint, r._consensus_timestamps)
                     for r in self._relays])

    def _update_relays_consensus_timestamps(self, previous_timestamps,
                                            last_timestamp):
        for r in self._relays:
            relay_previous_timestamps = \
                previous_timestamps.get(r.fingerprint, [])
            self.remove_old_consensus_timestamps(relay_previous_timestamps)
            # Then set old ones and last one.
            r.set_consensus_timestamps(relay_previous_timestamps,
                                       last_timestamp)

    def _refresh(self):
        # NOTE: this overwrites all relays, so it's lost the previous
        # information of the consensus attributes for each relay.
        # On future refactor, just update them with new values and add the
        # new ones.
        relays_previous_consensus_timestamps = \
            self._obtain_relays_previous_consensus_timestamps
        self._relays = self._init_relays()
        self._update_consensus_timestamps
        self._remove_old_consensus_timestamps
        self._update_relays_consensus_timestamps(
            relays_previous_consensus_timestamps, self.last_consensus
            )

    def exits_not_bad_allowing_port(self, port):
        return [r for r in self.exits
                if r.is_exit_not_bad_allowing_port(port)]
