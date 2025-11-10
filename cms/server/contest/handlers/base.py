#!/usr/bin/env python3

# Contest Management System - http://cms-dev.github.io/
# Copyright © 2010-2014 Giovanni Mascellani <mascellani@poisson.phc.unipi.it>
# Copyright © 2010-2016 Stefano Maggiolo <s.maggiolo@gmail.com>
# Copyright © 2010-2012 Matteo Boscariol <boscarim@hotmail.com>
# Copyright © 2012-2015 Luca Wehrstedt <luca.wehrstedt@gmail.com>
# Copyright © 2013 Bernard Blackham <bernard@largestprime.net>
# Copyright © 2014 Artem Iglikov <artem.iglikov@gmail.com>
# Copyright © 2014 Fabian Gundlach <320pointsguy@gmail.com>
# Copyright © 2015-2016 William Di Luigi <williamdiluigi@gmail.com>
# Copyright © 2016 Myungwoo Chun <mc.tamaki@gmail.com>
# Copyright © 2016 Amir Keivan Mohtashami <akmohtashami97@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Base handler classes for CWS.

"""

import logging
import traceback

import collections

from cms.db.user import Participation

try:
    collections.MutableMapping
except:
    # Monkey-patch: Tornado 4.5.3 does not work on Python 3.11 by default
    collections.MutableMapping = collections.abc.MutableMapping

import tornado.web
from werkzeug.datastructures import LanguageAccept
from werkzeug.http import parse_accept_header

from cms.db import Contest
from cms.locale import DEFAULT_TRANSLATION, choose_language_code
from cms.server import CommonRequestHandler
from cmscommon.datetime import utc as utc_tzinfo
import typing

if typing.TYPE_CHECKING:
    from cms.server.contest.server import ContestWebServer


# ranido-begin
import hmac
import hashlib
import base64
import time
import re
# ranido-end

logger = logging.getLogger(__name__)


# ranido-begin
UA_SECRET = "1hrs5g1qs@svr-o(-3atjnz8evwmake03kyjwute023mdeu" # same as in django.settings
UA_MAX_AGE_SECONDS = 6*3600  # User-Agent valid for 6 hours
UA_VALIDATION_ENABLED = False

def b64url_no_pad_decode(s: str) -> bytes:
    """
    Decode base64url without padding (inverse of b64url_no_pad from Django).
    """
    # Add padding if needed
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += '=' * padding
    
    # Replace URL-safe chars with standard base64 chars
    s = s.replace('-', '+').replace('_', '/')
    
    return base64.b64decode(s)


def parse_exam_ua(ua_string: str) -> dict | None:
    """
    Parse the ExamKit User-Agent string.
    
    Format: ExamKit/1 id=CONTESTANT ts=TIMESTAMP nonce=NONCE sig=SIGNATURE
    
    Returns:
        dict with keys: id, ts, nonce, sig
        None if parsing fails
    """
    if not ua_string or "ExamKit" not in ua_string:
        return None
    
    try:
        # Parse using regex
        pattern = r'ExamKit/1\s+id=([^\s]+)\s+ts=(\d+)\s+nonce=([^\s]+)\s+sig=([^\s]+)'
        match = re.match(pattern, ua_string)
        
        if not match:
            return None
        
        return {
            'id': match.group(1),
            'ts': int(match.group(2)),
            'nonce': match.group(3),
            'sig': match.group(4)
        }
    except Exception as e:
        logger.warning(f"Failed to parse User-Agent: {e}")
        return None


def verify_exam_ua(ua_string: str) -> tuple[bool, str, dict | None]:
    """
    Verify the ExamKit User-Agent signature and timestamp.
    
    Returns:
        (valid: bool, error_message: str, parsed_data: dict | None)
    """
    if not UA_VALIDATION_ENABLED:
        logger.debug("User-Agent validation is disabled")
        return True, "", None
    
    if not UA_SECRET:
        logger.error("UA_SECRET not configured - cannot validate User-Agent")
        return False, "Server configuration error", None
    
    # Parse the User-Agent
    parsed = parse_exam_ua(ua_string)
    if not parsed:
        logger.warning(f"Invalid User-Agent format: {ua_string[:100]}")
        return False, "Invalid User-Agent format", None
    
    contestant_id = parsed['id']
    ts = parsed['ts']
    nonce = parsed['nonce']
    sig_received = parsed['sig']
    
    # Check timestamp freshness
    now = int(time.time())
    age = now - ts
    
    if age < 0:
        logger.warning(f"User-Agent from future for {contestant_id}: ts={ts}, now={now}")
        return False, "User-Agent timestamp is in the future", parsed
    
    if age > UA_MAX_AGE_SECONDS:
        logger.warning(f"Expired User-Agent for {contestant_id}: age={age}s (max={UA_MAX_AGE_SECONDS}s)")
        return False, f"User-Agent expired (age: {age}s)", parsed
    
    # Reconstruct the payload and verify signature
    payload = f"{contestant_id}|{ts}|{nonce}".encode("utf-8")
    
    try:
        mac = hmac.new(UA_SECRET.encode("utf-8"), payload, hashlib.sha256).digest()
        # Encode to base64url without padding (same as Django side)
        sig_computed = base64.urlsafe_b64encode(mac).decode('ascii').rstrip('=')
        
        # Constant-time comparison
        if not hmac.compare_digest(sig_computed, sig_received):
            logger.warning(f"Invalid User-Agent signature for {contestant_id}")
            return False, "Invalid User-Agent signature", parsed
        
    except Exception as e:
        logger.error(f"Error verifying User-Agent signature: {e}")
        return False, "Signature verification error", parsed
    
    logger.debug(f"Valid User-Agent for contestant {contestant_id}")
    return True, "", parsed

# ranido-end

class BaseHandler(CommonRequestHandler):
    """Base RequestHandler for this application.

    This will also handle the contest list on the homepage.

    """
    current_user: Participation | None
    service: "ContestWebServer"
    api_request: bool

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # The list of interface translations the user can choose from.
        self.available_translations = self.service.translations
        # The translation that best matches the user's system settings
        # (as reflected by the browser in the HTTP request's
        # Accept-Language header).
        self.automatic_translation = DEFAULT_TRANSLATION
        # The translation that the user specifically manually picked.
        self.cookie_translation = None
        # The translation that we are going to use.
        self.translation = DEFAULT_TRANSLATION
        self._ = self.translation.gettext
        self.n_ = self.translation.ngettext
        # Is this a request on an API endpoint?
        self.api_request = False

        # ranido-begin
        # User-Agent validation data
        self.ua_validated = False
        self.ua_contestant_id = None
        # ranido-end

    def render(self, template_name, **params):
        t = self.service.jinja2_environment.get_template(template_name)
        for chunk in t.generate(**params):
            self.write(chunk)

    def prepare(self):
        """This method is executed at the beginning of each request.

        """
        super().prepare()
        self.setup_locale()

        # ranido-begin
        # Validate User-Agent for all requests
        self.validate_user_agent()
        # ranido-end

    # ranido-begin
    def validate_user_agent(self):
        """
        Validate the User-Agent header and reject invalid requests.
        """
        # Get User-Agent header
        ua_string = self.request.headers.get("User-Agent", "")
        
        # Verify the User-Agent
        valid, error_msg, parsed_data = verify_exam_ua(ua_string)
        
        if not valid:
            logger.warning(
                f"Rejected request from {self.request.remote_ip}: {error_msg}"
            )
            # Return 404 Not Found
            raise tornado.web.HTTPError(404)
        
        # Store validated data for use in handlers
        if parsed_data:
            self.ua_validated = True
            self.ua_contestant_id = parsed_data['id']
            logger.debug(
                f"Validated User-Agent for contestant {self.ua_contestant_id} "
            )    
    # ranido-end

    def setup_locale(self):
        lang_codes = list(self.available_translations.keys())

        browser_langs = parse_accept_header(
            self.request.headers.get("Accept-Language", ""),
            LanguageAccept).values()
        automatic_lang = choose_language_code(browser_langs, lang_codes)
        if automatic_lang is None:
            automatic_lang = lang_codes[0]
        self.automatic_translation = \
            self.available_translations[automatic_lang]

        cookie_lang = self.get_cookie("language", None)
        if cookie_lang is not None:
            chosen_lang = \
                choose_language_code([cookie_lang, automatic_lang], lang_codes)
            if chosen_lang == cookie_lang:
                self.cookie_translation = \
                    self.available_translations[cookie_lang]
        else:
            chosen_lang = automatic_lang
        self.translation = self.available_translations[chosen_lang]

        self._ = self.translation.gettext
        self.n_ = self.translation.ngettext

        self.set_header("Content-Language", chosen_lang)

    def render_params(self) -> dict:
        """Return the default render params used by almost all handlers.

        return: default render params

        """
        ret = {}
        ret["now"] = self.timestamp
        ret["utc"] = utc_tzinfo
        ret["url"] = self.url

        ret["available_translations"] = self.available_translations

        ret["cookie_translation"] = self.cookie_translation
        ret["automatic_translation"] = self.automatic_translation

        ret["translation"] = self.translation
        ret["gettext"] = self._
        ret["ngettext"] = self.n_

        # FIXME The handler provides too broad an access: its usage
        # should be extracted into with narrower-scoped parameters.
        ret["handler"] = self

        ret["xsrf_form_html"] = self.xsrf_form_html()

        # ranido-begin
        # Add User-Agent validation data to render params
        ret["ua_validated"] = self.ua_validated
        ret["ua_contestant_id"] = self.ua_contestant_id
        # ranido-end
        
        return ret

    def write_error(self, status_code, **kwargs):
        if "exc_info" in kwargs and \
                kwargs["exc_info"][0] != tornado.web.HTTPError:
            exc_info = kwargs["exc_info"]
            logger.error(
                "Uncaught exception (%r) while processing a request: %s",
                exc_info[1], ''.join(traceback.format_exception(*exc_info)))

        # We assume that if r_params is defined then we have at least
        # the data we need to display a basic template with the error
        # information. If r_params is not defined (i.e. something went
        # *really* bad) we simply return a basic textual error notice.
        if self.r_params is not None:
            self.render("error.html", status_code=status_code, **self.r_params)
        else:
            # ranido-begin
            self.write("Acesso indevido.")
            #self.write("A critical error has occurred :-(")
            # ranido-end
            self.finish()

    def is_multi_contest(self):
        """Return whether CWS serves all contests."""
        return self.service.contest_id is None

    def is_api(self):
        """Return whether it's an API request."""
        return self.api_request

    def get_boolean_argument(self, name: str, default: bool) -> bool:
        """Parse a Boolean request argument."""

        arg = self.get_argument(name, "")
        if arg == "":
            return default

        if arg == '0':
            return False
        elif arg == '1':
            return True
        else:
            raise ValueError(f"Cannot parse boolean argument {name}")


class ContestListHandler(BaseHandler):
    def get(self):
        self.r_params = self.render_params()
        # We need this to be computed for each request because we want to be
        # able to import new contests without having to restart CWS.
        contest_list = dict()
        for contest in self.sql_session.query(Contest).all():
            contest: Contest
            contest_list[contest.name] = contest
        self.render("contest_list.html", contest_list=contest_list,
                    **self.r_params)
