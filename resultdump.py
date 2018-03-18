import os
import time
from threading import Thread
from threading import Event
from queue import Queue
from queue import Empty
from datetime import date


class Result:
    def __init__(self, relay, circ, server_host, duration, amount):
        self._relay = relay
        self._circ = circ
        self._duration = duration
        self._amount = amount
        self._server_host = server_host
        self._time = time.time()

    @property
    def fingerprint(self):
        return self._relay.fingerprint

    @property
    def nickname(self):
        return self._relay.nickname

    @property
    def address(self):
        return self._relay.address

    @property
    def circ(self):
        return self._circ

    @property
    def time(self):
        return self._time

    @property
    def duration(self):
        return self._duration

    @property
    def amount(self):
        return self._amount

    @property
    def server_host(self):
        return self._server_host

    def __str__(self):
        d = {
            'fingerprint': self.fingerprint,
            'nickname': self.nickname,
            'time': self.time,
            'duration': self.duration,
            'amount': self.amount,
            'address': self.address,
            'circ': self.circ,
            'server_host': self.server_host
        }
        return str(d)


class ResultDump:
    def __init__(self, datadir, end_event):
        assert os.path.isdir(datadir)
        assert isinstance(end_event, Event)
        self.datadir = datadir
        self.end_event = end_event
        self.thread = Thread(target=self.enter)
        self.queue = Queue()
        self.thread.start()

    def write_result(self, result):
        assert isinstance(result, Result)
        dt = date.fromtimestamp(result.time)
        ext = '.txt'
        result_fname = os.path.join(
            self.datadir, '{}{}'.format(dt, ext))
        with open(result_fname, 'at') as fd:
            fd.write('{}\n'.format(str(result)))

    def enter(self):
        while not (self.end_event.is_set() and self.queue.empty()):
            try:
                event = self.queue.get(timeout=1)
            except Empty:
                continue
            result = event
            fp = result.fingerprint
            nick = result.nickname
            if result is None:
                print(nick, 'failed')
                continue
            elif not isinstance(result, Result):
                print(nick, 'failure', result, type(result))
                continue
            self.write_result(result)
            amount = result.amount
            duration = result.duration
            rate = amount / duration
            rate = rate * 8 / 1024 / 1024
            print(fp, nick, rate, duration)
