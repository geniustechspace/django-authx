r"""
______ _____ _____ _____    __
| ___ \  ___/  ___|_   _|  / _|                                           | |
| |_/ / |__ \ `--.  | |   | |_ _ __ __ _ _ __ ___   _____      _____  _ __| |__
|    /|  __| `--. \ | |   |  _| '__/ _` | '_ ` _ \ / _ \ \ /\ / / _ \| '__| |/ /
| |\ \| |___/\__/ / | |   | | | | | (_| | | | | | |  __/\ V  V / (_) | |  |   <
\_| \_\____/\____/  \_/   |_| |_|  \__,_|_| |_| |_|\___| \_/\_/ \___/|_|  |_|\_|
"""

__title__ = "Django Auth Framework"
__version__ = "3.15.2"
__author__ = "Dominic M. Tuolong"
__license__ = "BSD 3-Clause"
__copyright__ = "Copyright 2011-2023 Encode OSS Ltd"

# Version synonym
VERSION = __version__

# Header encoding (see RFC5987)
HTTP_HEADER_ENCODING = "iso-8859-1"

# Default datetime input and output formats
ISO_8601 = "iso-8601"


class RemovedInDRF316Warning(DeprecationWarning):
    pass


class RemovedInDRF317Warning(PendingDeprecationWarning):
    pass
