# -*- coding: utf-8 -*-
"""Classes and functions that create the bandwidth measurements document
(bw) used by bandwidth authorities."""
import logging
import os
from stem import descriptor

from sbws import __version__
from sbws.globals import SPEC_VERSION, BW_LINE_SIZE
from sbws.util.filelock import DirectoryLock
from sbws.util.timestamp import (now_isodt_str, unixts_to_isodt_str)


log = logging.getLogger(__name__)

BANDWIDTH_FILE_KEY_VALUE_SEPARATOR_V1 = '='
BANDWIDTH_HEADER_TERMINATOR_V11 = '====='
# Regex
# word=word
KEY_VALUE_REGEX = '(\w+)%s(\w+)' % BANDWIDTH_FILE_KEY_VALUE_SEPARATOR_V1
KEY_VALUE_LINE_REGEX = '^%s+$' % KEY_VALUE_REGEX
KEY_VALUES_LINE_REGEX = ''  # TBD
TERMINATOR_LINE_REGEX = '^%s$' % BANDWIDTH_HEADER_TERMINATOR_V11
TIMESTAMP_LINE_REGEX = '^(\d{10})$'


# Bandwidth File header Keys
# ==========================
# List of the extra KeyValues accepted by the class
BANDWIDTH_HEADER_KEY_VALUES_V11 = [
    'software', 'software_version', 'file_created',
    'earliest_bandwidth', 'generator_started'
    ]
BANDWIDTH_HEADER_STATS_KEY_VALUES_V11 = [
    'number_eligible_relays', 'minimum_number_eligible_relays',
    'number_consensus_relays', 'percent_eligible_relays',
    'minimum_percent_eligible_relays'
    ]
BANDWIDTH_HEADER_KEY_VALUES_INT = BANDWIDTH_HEADER_STATS_KEY_VALUES_V11

# List of all unordered KeyValues currently being used to generate the file
BANDWIDTH_HEADER_UNORDERED_KEY_VALUES_V11 = BANDWIDTH_HEADER_KEY_VALUES_V11 \
    + BANDWIDTH_HEADER_STATS_KEY_VALUES_V11 + ['latest_bandwidth']

# List of all the KeyValues currently being used to generate the file
# ``version`` is the only KeyValue which possition matters.
BANDWIDTH_HEADER_ALL_KEY_VALUES_V11 = ['version'] \
    + BANDWIDTH_HEADER_UNORDERED_KEY_VALUES_V11
BANDWIDTH_HEADER_TERMINATOR_LINE_V11 = \
    BANDWIDTH_HEADER_TERMINATOR_V11 + '\n'

# Bandwidth File Lines Keys
# =========================
# Bandwidth file lines have several keyvalues in one line
BANDWIDTH_LINE_KEY_VALUES_SEPARATOR_V1 = ' '

BANDWIDTH_LINE_KEY_VALUES_V10 = ['node_id', 'bw']
BANDWIDTH_LINE_KEY_VALUES_V11 = \
    BANDWIDTH_LINE_KEY_VALUES_V10 + \
    ['master_key_ed25519', 'nick', 'rtt', 'time',
     'success', 'error_stream', 'error_circ', 'error_misc']
BANDWIDTH_LINE_KEY_VALUES_BANDWIDTH_VALUES_V11 = [
    'bw_median', 'bw_mean', 'desc_bw_avg', 'desc_bw_bur',
    'desc_bw_obs_last', 'desc_bw_obs_mean',
    'consensus_bandwidth',
    'consensus_bandwidth_is_unmeasured']

BANDWIDTH_LINE_KEY_VALUES_ALL_V11 = \
    BANDWIDTH_LINE_KEY_VALUES_V10 \
    + BANDWIDTH_LINE_KEY_VALUES_BANDWIDTH_VALUES_V11

BANDWIDTH_LINE_KEY_VALUES_INT = \
    ['bw', 'rtt', 'success', 'error_stream',
     'error_circ', 'error_misc'] \
    + BANDWIDTH_LINE_KEY_VALUES_BANDWIDTH_VALUES_V11
BANDWIDTH_LINE_KEY_VALUES_STR = \
    list(set(BANDWIDTH_LINE_KEY_VALUES_ALL_V11).difference(
        set(BANDWIDTH_LINE_KEY_VALUES_INT)))

REQUIRED_FIELDS = BANDWIDTH_LINE_KEY_VALUES_V10
SINGLE_FIELDS = BANDWIDTH_LINE_KEY_VALUES_V11 \
    + BANDWIDTH_LINE_KEY_VALUES_BANDWIDTH_VALUES_V11


class BandwidthHeader(object):
    """Bandwidth File header following bandwidth-file-spec version 1.X."""
    def __init__(self, timestamp, **kwargs):
        """
        :param str timestamp: timestamp in Unix Epoch seconds of the most
            recent bandwidth measurement.
        :param dict kwargs: Bandwidth File header KeyValues to initialize
            the attributes.

        """
        assert isinstance(timestamp, str)
        for k, v in kwargs.items():
            assert isinstance(k, str)
            assert isinstance(v, str)
        # FIXME
        self.timestamp = timestamp
        # KeyValues with default value when not given by kwargs
        self.version = kwargs.get('version', SPEC_VERSION)
        self.software = kwargs.get('software', 'sbws')
        self.software_version = kwargs.get('software_version', __version__)
        self.file_created = kwargs.get('file_created',
                                       now_isodt_str())
        # latest_bandwidth should not be in kwargs, since it MUST be the
        # same as timestamp. Ignore it if it is.
        self.latest_bandwidth = unixts_to_isodt_str(timestamp)
        [setattr(self, k, v) for k, v in kwargs.items()
         if k in BANDWIDTH_HEADER_ALL_KEY_VALUES_V11]

    def __str__(self):
        if self.version.startswith('1.'):
            return self._header_str_v1
        return self._header_str_v2

    @classmethod
    def parse_header_lines_v11(cls, lines):
        """
        :param list lines: list of lines to parse
        :returns: tuple of BandwidthHeader object and non-header lines
        """
        assert isinstance(lines, list)
        timestamp = lines[0]
        kwargs = dict([line.split(BANDWIDTH_FILE_KEY_VALUE_SEPARATOR_V1)
                       for line in lines
                       if line.split(BANDWIDTH_FILE_KEY_VALUE_SEPARATOR_V1)[0]
                       in BANDWIDTH_HEADER_ALL_KEY_VALUES_V11])
        header = cls(timestamp, **kwargs)
        # last line is new line
        return header

    @classmethod
    def from_text_v11(self, text):
        """
        :param str text: text to parse
        :returns: tuple of BandwidthHeader object and non-header lines
        """
        assert isinstance(text, str)
        return self.parse_header_lines_v11(text.split('\n'))

    @classmethod
    def parse_header_lines_v10(cls, lines):
        """
        :param list lines: list of lines to parse
        :returns: tuple of BandwidthHeader object and non-header lines
        """
        assert isinstance(lines, list)
        header = cls(lines[0])
        # last line is new line
        return header

    @property
    def keyvalues_tuple_list(self):
        """Return a list of all KeyValue tuples."""
        keyvalues = sorted(
            [(k, getattr(self, k, None))
             for k in BANDWIDTH_HEADER_ALL_KEY_VALUES_V11
             # Do not include keys that has no value
             if getattr(self, k, None) is not None]
            )
        return keyvalues

    @property
    def keyvalues_str_list_v1(self):
        """Return KeyValue list of strings following spec v1.X.X."""
        keyvalues = [self.timestamp] \
            + [BANDWIDTH_FILE_KEY_VALUE_SEPARATOR_V1.join([k, v])
               for k, v in self.keyvalues_tuple_list]
        return keyvalues

    @property
    def _header_str_v1(self):
        """Return header string following spec v1.X.X."""
        header_str = '\n'.join(self.keyvalues_str_list_v1) + '\n'
        return header_str


class BandwidthLine(object):
    """Bandwidth List line following the bandwidth-file-spec version 1.X."""
    def __init__(self, node_id=None, bw=None, **kwargs):
        """
        ``node_id`` and ``bw`` are the only mandatory KeyValues in all
        versions. Allow to initialize the line passing them as part of kwargs.

        :param dict kwargs: extra headers.
            KeyValues in version 1.1.0:
            - node_id, str
            - bw, int
            - nickname, str
            - master_key_ed25519, str
            - rtt, int
            - time, str
            - sucess, int
            - error_stream, int
            - error_circ, int
            - error_misc, int

        """
        # Check types
        node_id = node_id or kwargs.get('node_id', None)
        bw = bw or kwargs.get('bw', None)
        assert isinstance(node_id, str) and node_id.startswith("$")
        assert isinstance(bw, int)
        for k, v in kwargs.items():
            if k in BANDWIDTH_LINE_KEY_VALUES_INT:
                assert isinstance(v, int)
            elif k in BANDWIDTH_LINE_KEY_VALUES_STR:
                assert isinstance(v, str)
        self.node_id = node_id
        self.bw = bw
        # Set the attributes
        [setattr(self, k, v) for k, v in kwargs.items()
         if k in BANDWIDTH_LINE_KEY_VALUES_ALL_V11]

    def __str__(self):
        # FIXME
        return self._bandwidth_line_str_v1

    @classmethod
    def parse_bandwidth_line_str_v1(cls, line_str):
        if line_str == '':
            return None
        assert isinstance(line_str, str)
        assert 'bw' in line_str
        assert 'node_id' in line_str
        kwargs = dict(
            [kv.split(BANDWIDTH_FILE_KEY_VALUE_SEPARATOR_V1)
             for kv in line_str.split(BANDWIDTH_LINE_KEY_VALUES_SEPARATOR_V1)
             if kv.split(BANDWIDTH_FILE_KEY_VALUE_SEPARATOR_V1)[0]
             in BANDWIDTH_LINE_KEY_VALUES_ALL_V11]
             )
        # Convert int values to int
        for k, v in kwargs.items():
            if k in BANDWIDTH_LINE_KEY_VALUES_INT:
                kwargs[k] = int(v)
        return cls(**kwargs)

    @property
    def bw_keyvalues_tuple_list(self):
        """Return list of KeyValue Bandwidth Line tuples."""
        # sort the list to generate determinist headers
        keyvalues_tuple_list = sorted(
            [(k, v) for k, v in self.__dict__.items()
             if k in BANDWIDTH_LINE_KEY_VALUES_ALL_V11])
        return keyvalues_tuple_list

    @property
    def bw_keyvalues_str_list_v1(self):
        """Return list of KeyValue Bandwidth Line strings following
        spec v1.X.X.
        """
        bw_keyvalue_str = \
            [BANDWIDTH_FILE_KEY_VALUE_SEPARATOR_V1.join([k, str(v)])
             for k, v in self.bw_keyvalues_tuple_list]
        return bw_keyvalue_str

    @property
    def _bandwidth_line_str_v1(self):
        """Return Bandwidth Line string following spec v1.X.X."""
        bandwidth_line_str = BANDWIDTH_LINE_KEY_VALUES_SEPARATOR_V1.join(
                        self.bw_keyvalues_str_list_v1) + '\n'
        if len(bandwidth_line_str) > BW_LINE_SIZE:
            # if this is the case, probably there are too many KeyValues,
            # or the limit needs to be changed in Tor
            log.warn("The bandwidth line %s is longer than %s",
                     len(bandwidth_line_str), BW_LINE_SIZE)
        return bandwidth_line_str


class BandwidthFile(object):
    """Bandwidth File following bandwidth-file-spec."""

    def __init__(self, bandwidth_header, bandwidth_lines):
        """

        :param BandwidthHeader bandwidth_header: header
        :param list bandwidth_lines: list of BandwidthLine objects

        """
        self.header = bandwidth_header
        self.bandwidth_lines = bandwidth_lines

    def __str__(self):
        # FIXME
        if self.header.version.startswith('1.'):
            return self._bandwidth_file_str_v1

    @property
    def _bandwidth_file_str_v1(self):
        return str(self.header) + BANDWIDTH_HEADER_TERMINATOR_LINE_V11 \
            + ''.join([str(bw_line) for bw_line in self.bandwidth_lines])

    @staticmethod
    def parse_lines_v11(lines):
        try:
            index_terminator = lines.index(BANDWIDTH_HEADER_TERMINATOR_V11)
        except ValueError:
            log.debug('It is not a Bandwidth File or it is not version 1.0.')
            return None, None
        header = BandwidthHeader.parse_header_lines_v11(
            lines[0:index_terminator])
        # Last line should be a new line
        bandwidth_lines = [BandwidthLine.parse_bandwidth_line_str_v1(line)
                           for line in lines[index_terminator + 1:-1]
                           if line]
        return header, bandwidth_lines

    @staticmethod
    def parse_lines_v10(lines):
        header = BandwidthHeader.parse_header_lines_v10(lines[0])
        bandwidth_lines = sorted(
            [BandwidthLine.parse_bandwidth_line_str_v1(line)
             for line in lines[1:-1]], key=lambda line: line.bw)
        return header, bandwidth_lines

    def parse_lines(self, lines):
        if BANDWIDTH_HEADER_TERMINATOR_V11 in lines:
            header, lines = self.parse_lines_v11(lines)
        else:
            header, lines = self.parse_lines_v10(lines)
        return header, lines

    @classmethod
    def parse_content(cls, text):
        lines = text.split('\n')
        header, lines = cls.parse_lines(cls, lines)
        return cls(header, lines)

    @classmethod
    def from_file_path(cls, fpath):
        log.info('Parsing bandwidth file %s', fpath)
        with open(fpath) as fd:
            text = fd.read()
        return cls.parse_content(text)

    def write(self, output):
        if output == '/dev/stdout':
            log.info("Writing to stdout is not supported.")
            return
        log.info('Writing bw file to %s', output)
        # To avoid inconsistent reads, the bandwidth data is written to an
        # archive path, then atomically symlinked to 'latest.bw'
        out_dir = os.path.dirname(output)
        out_link = os.path.join(out_dir, 'latest.bw')
        out_link_tmp = out_link + '.tmp'
        with DirectoryLock(out_dir):
            with open(output, 'wt') as fd:
                fd.write(str(self.header))
                for line in self.bandwidth_lines:
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


def _parse_file(bandwidth_file, validate=False, **kwargs):
    with open(bandwidth_file) as fd:
        bandwidth_content = fd.read()
    annotations = None
    bandwidth_text = bytes.join(b'', bandwidth_content)

    yield BandwidthDocument(bandwidth_text, validate, annotations, **kwargs)


class BandwidthDocument(descriptor.Descriptor, BandwidthFile):
    """"""
    def __init__(self, raw_contents, validate=False, annotations=None):
        """
        """
        super(BandwidthDocument, self).__init__(raw_contents,
                                                lazy_load=not validate)
        self._annotation_lines = []
        entry = self.parse_content(raw_contents)
        self._entries = [entry]

    @classmethod
    def content(cls, attr=None, exclude=(), sign=False):
        return cls.parse_content(attr)

    @classmethod
    def create(cls, attr=None, exclude=(), validate=True, sign=False, signing_key=None):
        return cls.parse_content(attr)

    def _required_fields(self):
        return REQUIRED_FIELDS

    def _single_fields(self):
      return REQUIRED_FIELDS + SINGLE_FIELDS
