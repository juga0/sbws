from stem.descriptor.router_status_entry import RouterStatusEntryV3
from stem.descriptor.server_descriptor import ServerDescriptor
from stem import Flag, DescriptorUnavailable, ControllerError
import random
import time
import logging
from threading import Lock

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
            self.consensus_count = 1
        else:
            try:
                self._ns = cont.get_network_status(fp, default=None)
                self.consensus_count = 1
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

    def _from_desc(self, attr):
        if not self._desc:
            return None
        return getattr(self._desc, attr, None)

    def _from_ns(self, attr):
        if not self._ns:
            return None
        return getattr(self._ns, attr, None)

    @property
    def increment_consensus_count(self):
        self.consensus_count += 1

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
    # There is a new consensus every hour.
    # Assume that every time the list is refreshed, the consensus is new.
    REFRESH_INTERVAL = 60 * 60  # seconds

    def __init__(self, args, conf, controller):
        self._controller = controller
        self.rng = random.SystemRandom()
        self._refresh_lock = Lock()
        self._refresh()

    def _need_refresh(self):
        return time.time() >= self._last_refresh + self.REFRESH_INTERVAL

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

    @staticmethod
    def relay_with_fingerprint_in_list(relays, fingerprint):
        relay = [r for r in relays if r.fingerprint == fingerprint]
        if relay:
            return relay[0]
        return None

    def update_relay_list(self, new_relays):
        # If there was not already a list of relays, consensus_count will be
        # 1 in new_relays
        old_fps = [r.fingerprint for r in getattr(self, '_relays', [])]
        new_fps = [r.fingerprint for r in new_relays]
        fps_to_rm = set(old_fps).difference(set(new_fps))
        log.debug("Number of relays no longer in the consensus: %s",
                  len(fps_to_rm))
        fps_to_add = set(new_fps).difference(set(old_fps))
        log.debug("Number of relays new in the consensus: %s",
                  len(fps_to_add))
        fps_to_increment = set(old_fps).intersection(set(new_fps))

        updated_relays = []
        for fp in fps_to_add:
            r = self.relay_with_fingerprint_in_list(new_relays, fp)
            updated_relays.append(r)
        for fp in fps_to_increment:
            r = self.relay_with_fingerprint_in_list(self._relays, fp)
            r.increment_consensus_count
            updated_relays.append(r)
        return updated_relays

    def _refresh(self):
        new_relays = self._init_relays()
        self._relays = self.update_relay_list(new_relays)
        self._last_refresh = time.time()

    def exits_not_bad_allowing_port(self, port):
        return [r for r in self.exits
                if r.is_exit_not_bad_allowing_port(port)]
