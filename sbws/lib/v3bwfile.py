# -*- coding: utf-8 -*-
"""Classes and functions that create the bandwidth measurements document
(v3bw) used by bandwidth authorities."""

import copy
import logging
import os
from statistics import median, mean

from sbws import __version__
from sbws.globals import (SPEC_VERSION, BW_LINE_SIZE, SBWS_SCALE_CONSTANT,
                          TORFLOW_SCALING, SBWS_SCALING, TORFLOW_BW_MARGIN)
from sbws.lib.resultdump import ResultSuccess, _ResultType
from sbws.util.filelock import DirectoryLock
from sbws.util.timestamp import now_isodt_str, unixts_to_isodt_str
from sbws.util.state import State

log = logging.getLogger(__name__)

LINE_SEP = '\n'
KEYVALUE_SEP_V110 = '='
# Not used so far.
# In some future, we intend to format Bandwidth List files in the same way
# as the Tor's XXX documents, and that would be Bandwidth List specification
# V2.0.0.
KEYVALUE_SEP_V200 = ' '
# List of the extra KeyValues accepted by the class
EXTRA_ARG_KEYVALUES = ['software', 'software_version', 'file_created',
                       'earliest_bandwidth', 'generator_started']
# List of all unordered KeyValues currently being used to generate the file
UNORDERED_KEYVALUES = EXTRA_ARG_KEYVALUES + ['latest_bandwidth']
# List of all the KeyValues currently being used to generate the file
ALL_KEYVALUES = ['version'] + UNORDERED_KEYVALUES
TERMINATOR = '===='
# Num header lines in v1.1.0 using all the KeyValues
NUM_LINES_HEADER_V110 = len(ALL_KEYVALUES) + 2
LINE_TERMINATOR = TERMINATOR + LINE_SEP

# KeyValue separator in Bandwidth Lines
BW_KEYVALUE_SEP_V110 = ' '
BW_EXTRA_ARG_KEYVALUES = ['master_key_ed25519', 'nick', 'rtt', 'time',
                          'success', 'error_stream', 'error_circ',
                          'error_misc']
BW_KEYVALUES_INT = ['bw', 'rtt', 'success', 'error_stream',
                    'error_circ', 'error_misc']
BW_KEYVALUES = ['node_id', 'bw'] + BW_EXTRA_ARG_KEYVALUES


def num_results_of_type(results, type_str):
    return len([r for r in results if r.type == type_str])


# Better way to use enums?
def result_type_to_key(type_str):
    return type_str.replace('-', '_')


class V3BWHeader(object):
    """
    Create a bandwidth measurements (V3bw) header
    following bandwidth measurements document spec version 1.1.0.

    :param str timestamp: timestamp in Unix Epoch seconds of the most recent
        generator result.
    :param str version: the spec version
    :param str software: the name of the software that generates this
    :param str software_version: the version of the software
    :param dict kwargs: extra headers. Currently supported:

        - earliest_bandwidth: str, ISO 8601 timestamp in UTC time zone
          when the first bandwidth was obtained
        - generator_started: str, ISO 8601 timestamp in UTC time zone
          when the generator started
    """
    def __init__(self, timestamp, **kwargs):
        assert isinstance(timestamp, str)
        for v in kwargs.values():
            assert isinstance(v, str)
        self.timestamp = timestamp
        # KeyValues with default value when not given by kwargs
        self.version = kwargs.get('version', SPEC_VERSION)
        self.software = kwargs.get('software', 'sbws')
        self.software_version = kwargs.get('software_version', __version__)
        self.file_created = kwargs.get('file_created', now_isodt_str())
        # latest_bandwidth should not be in kwargs, since it MUST be the
        # same as timestamp
        self.latest_bandwidth = unixts_to_isodt_str(timestamp)
        [setattr(self, k, v) for k, v in kwargs.items()
         if k in EXTRA_ARG_KEYVALUES]

    @property
    def keyvalue_unordered_tuple_ls(self):
        """Return list of KeyValue tuples that do not have specific order."""
        # sort the list to generate determinist headers
        keyvalue_tuple_ls = sorted([(k, v) for k, v in self.__dict__.items()
                                    if k in UNORDERED_KEYVALUES])
        return keyvalue_tuple_ls

    @property
    def keyvalue_tuple_ls(self):
        """Return list of all KeyValue tuples"""
        return [('version', self.version)] + self.keyvalue_unordered_tuple_ls

    @property
    def keyvalue_v110str_ls(self):
        """Return KeyValue list of strings following spec v1.1.0."""
        keyvalues = [self.timestamp] + [KEYVALUE_SEP_V110.join([k, v])
                                        for k, v in self.keyvalue_tuple_ls]
        return keyvalues

    @property
    def strv110(self):
        """Return header string following spec v1.1.0."""
        header_str = LINE_SEP.join(self.keyvalue_v110str_ls) + LINE_SEP + \
            LINE_TERMINATOR
        return header_str

    @property
    def keyvalue_v200_ls(self):
        """Return KeyValue list of strings following spec v2.0.0."""
        keyvalue = [self.timestamp] + [KEYVALUE_SEP_V200.join([k, v])
                                       for k, v in self.keyvalue_tuple_ls]
        return keyvalue

    @property
    def strv200(self):
        """Return header string following spec v2.0.0."""
        header_str = LINE_SEP.join(self.keyvalue_v200_ls) + LINE_SEP + \
            LINE_TERMINATOR
        return header_str

    def __str__(self):
        if self.version == '1.1.0':
            return self.strv110
        return self.strv200

    @classmethod
    def from_lines_v110(cls, lines):
        """
        :param list lines: list of lines to parse
        :returns: tuple of V3BWHeader object and non-header lines
        """
        assert isinstance(lines, list)
        try:
            index_terminator = lines.index(TERMINATOR)
        except ValueError:
            # is not a bw file or is v100
            log.warn('Terminator is not in lines')
            return None
        ts = lines[0]
        kwargs = dict([l.split(KEYVALUE_SEP_V110)
                       for l in lines[:index_terminator]
                       if l.split(KEYVALUE_SEP_V110)[0] in ALL_KEYVALUES])
        h = cls(ts, **kwargs)
        # last line is new line
        return h, lines[index_terminator + 1:-1]

    @classmethod
    def from_text_v110(self, text):
        """
        :param str text: text to parse
        :returns: tuple of V3BWHeader object and non-header lines
        """
        assert isinstance(text, str)
        return self.from_lines_v110(text.split(LINE_SEP))

    @property
    def num_lines(self):
        return len(self.__str__().split(LINE_SEP))

    @staticmethod
    def generator_started_from_file(conf):
        '''
        ISO formatted timestamp for the time when the scanner process most
        recently started.
        '''
        state = State(conf.getpath('paths', 'state_fname'))
        if 'scanner_started' in state:
            return state['scanner_started']
        else:
            return None

    @staticmethod
    def latest_bandwidth_from_results(results):
        return round(max([r.time for fp in results for r in results[fp]]))

    @staticmethod
    def earliest_bandwidth_from_results(results):
        return round(min([r.time for fp in results for r in results[fp]]))

    @classmethod
    def from_results(cls, conf, results):
        kwargs = dict()
        latest_bandwidth = cls.latest_bandwidth_from_results(results)
        earliest_bandwidth = cls.earliest_bandwidth_from_results(results)
        generator_started = cls.generator_started_from_file(conf)
        timestamp = str(latest_bandwidth)
        kwargs['latest_bandwidth'] = unixts_to_isodt_str(latest_bandwidth)
        kwargs['earliest_bandwidth'] = unixts_to_isodt_str(earliest_bandwidth)
        if generator_started is not None:
            kwargs['generator_started'] = generator_started
        h = cls(timestamp, **kwargs)
        return h


class V3BWLine(object):
    """
    Create a Bandwidth List line following the spec version 1.1.0.

    :param str node_id:
    :param int bw:
    :param dict kwargs: extra headers. Currently supported:

        - nickname, str
        - master_key_ed25519, str
        - rtt, int
        - time, str
        - sucess, int
        - error_stream, int
        - error_circ, int
        - error_misc, int
    """
    def __init__(self, node_id, bw, **kwargs):
        assert isinstance(node_id, str)
        assert isinstance(bw, int)
        assert node_id.startswith('$')
        self.node_id = node_id
        self.bw = bw
        [setattr(self, k, v) for k, v in kwargs.items()
         if k in BW_EXTRA_ARG_KEYVALUES]

    def __str__(self):
        return self.bw_strv110

    @classmethod
    def from_bw_line_v110(cls, line):
        # log.debug('Parsing bandwidth line.')
        assert isinstance(line, str)
        kwargs = dict([kv.split(KEYVALUE_SEP_V110)
                       for kv in line.split(BW_KEYVALUE_SEP_V110)
                       if kv.split(KEYVALUE_SEP_V110)[0] in BW_KEYVALUES])
        for k, v in kwargs.items():
            if k in BW_KEYVALUES_INT:
                kwargs[k] = int(v)
        node_id = kwargs['node_id']
        bw = kwargs['bw']
        del kwargs['node_id']
        del kwargs['bw']
        bw_line = cls(node_id, bw, **kwargs)
        return bw_line

    @property
    def bw_keyvalue_tuple_ls(self):
        """Return list of KeyValue Bandwidth Line tuples."""
        # sort the list to generate determinist headers
        keyvalue_tuple_ls = sorted([(k, v) for k, v in self.__dict__.items()
                                    if k in BW_KEYVALUES])
        return keyvalue_tuple_ls

    @property
    def bw_keyvalue_v110str_ls(self):
        """Return list of KeyValue Bandwidth Line strings following
        spec v1.1.0.
        """
        bw_keyvalue_str = [KEYVALUE_SEP_V110 .join([k, str(v)])
                           for k, v in self.bw_keyvalue_tuple_ls]
        return bw_keyvalue_str

    @property
    def bw_strv110(self):
        """Return Bandwidth Line string following spec v1.1.0."""
        bw_line_str = BW_KEYVALUE_SEP_V110.join(
                        self.bw_keyvalue_v110str_ls) + LINE_SEP
        if len(bw_line_str) > BW_LINE_SIZE:
            # if this is the case, probably there are too many KeyValues,
            # or the limit needs to be changed in Tor
            log.warn("The bandwidth line %s is longer than %s",
                     len(bw_line_str), BW_LINE_SIZE)
        return bw_line_str

    @staticmethod
    def bw_from_results(results):
        median_bw = median([dl['amount'] / dl['duration']
                            for r in results for dl in r.downloads])
        # If a relay has MaxAdvertisedBandwidth set, they may be capable of
        # some large amount of bandwidth but prefer if they didn't receive it.
        # We also could have managed to measure them faster than their
        # {,Relay}BandwidthRate somehow.
        #
        # See https://github.com/pastly/simple-bw-scanner/issues/155 and
        # https://trac.torproject.org/projects/tor/ticket/8494
        #
        # Note how this isn't some measured-by-us average of bandwidth. It's
        # the first value on the 'bandwidth' line in the relay's server
        # descriptor.
        bw = median_bw
        relay_average_bw = [r.relay_average_bandwidth for r in results
                            if r.relay_average_bandwidth is not None]
        if relay_average_bw:
            median_relay_average_bw = median(relay_average_bw)
            if median_bw > median_relay_average_bw:
                bw = median_relay_average_bw
        # convert to KB and ensure it's at least 1
        bw_kb = max(round(bw / 1024), 1)
        return bw_kb

    @staticmethod
    def last_time_from_results(results):
        return unixts_to_isodt_str(round(max([r.time for r in results])))

    @staticmethod
    def rtt_from_results(results):
        rtts = round(median([rtt * 1000 for r in results for rtt in r.rtts]))
        return rtts

    @staticmethod
    def result_types_from_results(results):
        rt_dict = dict([(result_type_to_key(rt.value),
                         num_results_of_type(results, rt.value))
                        for rt in _ResultType])
        return rt_dict

    @classmethod
    def from_results(cls, results):
        success_results = [r for r in results if isinstance(r, ResultSuccess)]
        # log.debug('len(success_results) %s', len(success_results))
        node_id = '$' + results[0].fingerprint
        bw = cls.bw_from_results(success_results)
        kwargs = dict()
        kwargs['nick'] = results[0].nickname
        if getattr(results[0], 'master_key_ed25519'):
            kwargs['master_key_ed25519'] = results[0].master_key_ed25519
        kwargs['rtt'] = cls.rtt_from_results(success_results)
        kwargs['time'] = cls.last_time_from_results(results)
        kwargs.update(cls.result_types_from_results(results))
        bwl = cls(node_id, bw, **kwargs)
        return bwl

    @classmethod
    def from_data(cls, data, fingerprint):
        assert fingerprint in data
        return cls.from_results(data[fingerprint])

    @staticmethod
    def bw_bs_median_from_results(results):
        return max(round(median([dl['amount'] / dl['duration']
                                 for r in results for dl in r.downloads])), 1)

    @staticmethod
    def bw_bs_mean_from_results(results):
        return max(round(mean([dl['amount'] / dl['duration']
                               for r in results for dl in r.downloads])), 1)


class V3BWFile(object):
    """
    Create a Bandwidth List file following spec version 1.1.0

    :param V3BWHeader v3bwheader: header
    :param list v3bwlines: V3BWLines
    """
    def __init__(self, v3bwheader, v3bwlines):
        self.header = v3bwheader
        self.bw_lines = v3bwlines

    def __str__(self):
        return str(self.header) + ''.join([str(bw_line)
                                           for bw_line in self.bw_lines])

    @classmethod
    def from_v110_lines(cls, fpath):
        log.info('Parsing bandwidth file %s', fpath)
        with open(fpath) as fd:
            text = fd.read()
        all_lines = text.split(LINE_SEP)
        header, lines = V3BWHeader.from_lines_v110(all_lines)
        bw_lines = [V3BWLine.from_bw_line_v110(line) for line in lines]
        return cls(header, bw_lines)

    @staticmethod
    def warn_if_not_accurate_enough(bw_lines,
                                    scale_constant=SBWS_SCALE_CONSTANT):
        margin = 0.001
        accuracy_ratio = mean([l.bw for l in bw_lines]) / scale_constant
        log.info('The generated lines are within {:.5}% of what they should '
                 'be'.format((1 - accuracy_ratio) * 100))
        if accuracy_ratio < 1 - margin or accuracy_ratio > 1 + margin:
            log.warning('There was %f%% error and only +/- %f%% is '
                        'allowed', (1 - accuracy_ratio) * 100, margin * 100)

    @staticmethod
    def bw_lines_sbws_scale(bw_lines, scale_constant=SBWS_SCALE_CONSTANT,
                            reverse=False):
        """
        Return a new V3BwLine list with their ``bw`` scaled using sbws method.

        :param list bw_lines: bw lines to scale, not self.bw_lines,
            since this method will be before self.bw_lines have been
            initialized.
        :param int scale_constant: the constant to multiply by the ratio and
            the bandwidth to obtain the new bandwidth
        :returns list: V3BwLine list

        :_math::

            bwscaled_i = min\left(
                \frac{bwdesc_i, bw_i \times scale_constant}{m}\right) \\
            = \frac{bwdesc_i, bw_i \times scale_constant} \times
              \sum_{i=1}^{n}bw_i}{n}\right)

        """
        # If a relay has MaxAdvertisedBandwidth set, they may be capable of
        # some large amount of bandwidth but prefer if they didn't receive it.
        # We also could have managed to measure them faster than their
        # {,Relay}BandwidthRate somehow.
        #
        # See https://github.com/pastly/simple-bw-scanner/issues/155 and
        # https://trac.torproject.org/projects/tor/ticket/8494
        #
        # Note how this isn't some measured-by-us average of bandwidth. It's
        # the first value on the 'bandwidth' line in the relay's server
        # descriptor.
        log.debug('Scaling bandwidth using sbws method.')
        m = mean([l.bw_bs_mean for l in bw_lines])
        bw_lines_scaled = copy.deepcopy(bw_lines)
        for l in bw_lines_scaled:
            # min is to limit the bw to descriptor average-bandwidth
            l.bw = max(round(min(l.desc_avg_bw_bs,
                                 l.bw_bs_median * scale_constant / m)
                             / 1000), 1)
        return sorted(bw_lines_scaled, key=lambda x: x.bw, reverse=reverse)

    @property
    def median_bw_lines(self):
        return max(round(median([l.bw for l in self.bw_lines])), 1)

    @property
    def mean_bw_lines(self):
        return max(round(mean([l.bw for l in self.bw_lines])), 1)

    @property
    def sum_bw_lines(self):
        return sum([l.bw for l in self.bw_lines])

    @property
    def max_bw_lines(self):
        return max([l.bw for l in self.bw_lines])

    @property
    def min_bw_lines(self):
        return min([l.bw for l in self.bw_lines])

    @property
    def num(self):
        return len(self.bw_lines)

    @property
    def info_stats(self):
        [log.info(': '.join([attr, str(getattr(self, attr))])) for attr in
         ['sum_bw_lines', 'mean_bw_lines', 'median_bw_lines', 'num',
          'max_bw_lines', 'min_bw_lines']]

    @classmethod
    def from_arg_results(cls, args, conf, results):
        bw_lines = [V3BWLine.from_results(results[fp]) for fp in results]
        bw_lines = sorted(bw_lines, key=lambda d: d.bw, reverse=True)
        if args.scale:
            bw_lines = scale_lines(bw_lines, args.scale_constant)
        header = V3BWHeader.from_results(conf, results)
        f = cls(header, bw_lines)
        return f

    @property
    def node_ids(self):
        """
        Used from external tool to plot.
        """
        return [l.node_id for l in self.bw_lines]

    @property
    def bw(self):
        """
        Used from external tool to plot.
        """
        return [l.bw for l in self.bw_lines]

    def bw_line_for_node_id(self, node_id):
        """Returns the bandwidth line for a given node fingerprint.

        Used to combine data when plotting.
        """
        if node_id in self.node_ids:
            return self.bw_lines[self.node_ids.index(node_id)]
        return None

    def to_plot(self, attrs=['bw'], sorted_by=None):
        """Return bandwidth data in a format useful for matplotlib.

        Used from external tool to plot.
        """
        x = [i for i in range(0, self.num)]
        log.debug(len(x))
        ys = [getattr(self, k) for k in attrs]
        log.debug([len(y) for y in ys])
        labels = attrs
        log.debug(labels)
        return x, ys, labels

    def write(self, output):
        if output == '/dev/stdout':
            log.info("Writing to stdout is not supported.")
            return
        log.info('Writing v3bw file to %s', output)
        # To avoid inconsistent reads, the bandwidth data is written to an
        # archive path, then atomically symlinked to 'latest.v3bw'
        out_dir = os.path.dirname(output)
        out_link = os.path.join(out_dir, 'latest.v3bw')
        out_link_tmp = out_link + '.tmp'
        with DirectoryLock(out_dir):
            with open(output, 'wt') as fd:
                fd.write(str(self.header))
                for line in self.bw_lines:
                    fd.write(str(line))
            output_basename = os.path.basename(output)
            # To atomically symlink a file, we need to create a temporary link,
            # then rename it to the final link name. (POSIX guarantees that
            # rename is atomic.)
            log.debug('Creating symlink {} -> {}.'
                      .format(out_link_tmp, output_basename))
            os.symlink(output_basename, out_link_tmp)
            log.debug('Renaming symlink {} -> {} to {} -> {}.'
                      .format(out_link_tmp, output_basename,
                              out_link, output_basename))
            os.rename(out_link_tmp, out_link)
