#
# Copyright 2017-2018 Government of Canada
# Public Services and Procurement Canada - buyandsell.gc.ca
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Utility functions and classes
"""

import json
import logging
import time

from .exchange import ExchangeMessage


class MessageEncoder(json.JSONEncoder):
    """
    Customize JSONEncoder to automatically encode :class:`ExchangeMessage` instances
    """
    def default(self, o):
        if isinstance(o, ExchangeMessage):
            return dict(o)
        return super(MessageEncoder, self).default(o)


class JsonRepr:
    """
    Utility class to avoid JSON encoding debug output unless needed
    """
    def __init__(self, value, indent=2):
        self.value = value
        self.indent = indent

    def __repr__(self):
        return json.dumps(self.value, indent=self.indent, cls=MessageEncoder)


def log_json(heading, data, logger=None, level=logging.DEBUG):
    """
    Utility method to log JSON data for debugging
    """
    if not logger:
        logger = logging.getLogger(__name__)
    msg = """
============================================================================
%s
%s
============================================================================
"""
    logger.log(level, msg, heading, JsonRepr(data))


def normalize_credential_ids(cred_ids) -> set:
    """
    Clean up credential ID input
    """
    if isinstance(cred_ids, str):
        cred_ids = [id.strip() for id in cred_ids.split(",")]
    if isinstance(cred_ids, list):
        cred_ids = set(filter(None, cred_ids))
    elif not isinstance(cred_ids, set):
        cred_ids = None
    return cred_ids



class Stats:
    """
    Measure combined statistics for various named tasks
    """

    class Timer:
        """
        An instance of a timer that can be used in a with statement
        """
        def __init__(self, stats, tasks, log_as=None):
            self.duration = None
            self.handle = None
            self.log_as = log_as
            self.stats = stats
            self.tasks = tasks

        def start(self):
            """
            Start the timer
            """
            self.handle = self.stats.start(*self.tasks, log_as=self.log_as)
            return self

        def end(self):
            """
            End the timer
            """
            if self.duration is None:
                self.duration = self.stats.end(self.handle)
            return self.duration

        def __enter__(self):
            return self.start()

        def __exit__(self, exception_type, exception_value, traceback):
            self.end()

    def __init__(self, logger=None, log_level=logging.DEBUG):
        self.count = {}
        self.current = {}
        self.logger = logger
        self.log_level = log_level
        self.max = {}
        self.min = {}
        self.total = {}

    def start(self, *tasks, log_as=None):
        """
        Start a new set of tasks
        """
        if tasks and not log_as:
            log_as = tasks[0]
        if log_as and self.logger:
            self.logger.log(self.log_level, ">>> %s", log_as)
        for task in tasks:
            self.current[task] = self.current.get(task, 0) + 1
        return (time.perf_counter(), tasks, log_as)

    def end(self, handle):
        """
        End a previously started set of tasks
        """
        (start, tasks, log_as) = handle
        diff = time.perf_counter() - start
        for task in tasks:
            self.current[task] -= 1
            if task in self.count:
                self.count[task] += 1
                self.max[task] = max(self.max[task], diff)
                self.min[task] = min(self.min[task], diff)
                self.total[task] += diff
            else:
                self.count[task] = 1
                self.max[task] = diff
                self.min[task] = diff
                self.total[task] = diff
        if log_as and self.logger:
            self.logger.log(self.log_level, "<<< %s (%0.5f)", log_as, diff)
        return diff

    def timer(self, *tasks, log_as=None):
        """
        Create a new timer for a set of tasks
        """
        return self.Timer(self, tasks, log_as=log_as)

    def results(self):
        return {
            "avg": {task: self.total[task] / self.count[task] for task in self.count},
            "count": self.count.copy(),
            "current": self.current.copy(),
            "max": self.max.copy(),
            "min": self.min.copy(),
            "total": self.total.copy(),
        }
