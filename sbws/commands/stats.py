from sbws.globals import (fail_hard, is_initted)
from sbws.lib.resultdump import Result
from sbws.lib.resultdump import ResultError
from sbws.lib.resultdump import ResultSuccess
from sbws.lib.resultdump import load_recent_results_in_datadir
from sbws.lib.resultdump import group_results_by_relay
from argparse import ArgumentDefaultsHelpFormatter
import os
import json
from datetime import date
from datetime import timedelta


def read_result_file(fname, starting_dict=None):
    data = starting_dict if starting_dict else {}
    with open(fname, 'rt') as fd:
        for line in fd:
            d = json.loads(line)
            res = Result.from_dict(d)
            fp = d['fingerprint']
            if fp not in data:
                data[fp] = []
            data[fp].append(res)
    return data


def print_stats(data):
    results = []
    for fp in data:
        results.extend(data[fp])
    error_results = [r for r in results if isinstance(r, ResultError)]
    success_results = [r for r in results if isinstance(r, ResultSuccess)]
    percent_success_results = 100 * len(success_results) / len(results)
    first_time = min([r.time for r in results])
    last_time = max([r.time for r in results])
    first = date.fromtimestamp(first_time)
    last = date.fromtimestamp(last_time)
    duration = timedelta(seconds=last_time-first_time)
    # remove microseconds for prettier printing
    duration = duration - timedelta(microseconds=duration.microseconds)
    print(len(data), 'relays have recent results')
    print(len(results), 'total results, and {:.1f}% are successes'.format(
        percent_success_results))
    print(len(success_results), 'success results and',
          len(error_results), 'error results')
    print('Results come from', first, 'to', last, 'over a period of',
          duration)


def gen_parser(sub):
    sub.add_parser('stats', formatter_class=ArgumentDefaultsHelpFormatter)


def main(args, conf, log_):
    global log
    log = log_
    if not is_initted(args.directory):
        fail_hard('Sbws isn\'t initialized. Try sbws init', log=log)

    datadir = conf['paths']['datadir']
    if not os.path.isdir(datadir):
        fail_hard(datadir, 'does not exist', log=log)

    fresh_days = conf.getint('general', 'data_period')
    results = load_recent_results_in_datadir(
        fresh_days, datadir, success_only=False, log_fn=log.debug)
    data = group_results_by_relay(results)
    print_stats(data)
