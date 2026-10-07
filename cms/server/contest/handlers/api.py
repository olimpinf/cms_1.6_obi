#!/usr/bin/env python3

# Contest Management System - http://cms-dev.github.io/
# Copyright © 2025 Luca Versari <veluca93@gmail.com>
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

"""API handlers for CMS.

"""

import ipaddress
import logging

from cms.db.submission import Submission
from cms.server import multi_contest
from cms.server.contest.authentication import validate_login
from cms.server.contest.submission import \
    UnacceptableSubmission, accept_submission
from .contest import ContestHandler, api_login_required
from ..phase_management import actual_phase_required

logger = logging.getLogger(__name__)


class ApiContestHandler(ContestHandler):
    """An extension of ContestHandler marking the request as a part of the API.

    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_request = True

    # ranido-begin
    # Allows EditorOBI (hosted on a different domain than this CMS instance,
    # e.g. editor.provas.ic.unicamp.br calling pratique.olimpiada.ic.unicamp.br
    # when opened from Pratique in a plain browser tab) to make cross-origin
    # API calls. Inside ExamLock this isn't needed -- its Electron main
    # process patches these same headers at the network layer instead (see
    # exam-app-branch-version2.0/main.js's webRequest.onHeadersReceived) --
    # but a plain browser has no equivalent, and this server otherwise sends
    # no CORS headers at all, so the browser blocks every request outright.
    #
    # Restricted to the one known editor origin rather than reflecting any
    # Origin, since requests here are authenticated via X-CMS-Authorization
    # (a real bearer-style credential, not implicitly-sent cookies) -- no
    # reason to widen this beyond the one caller that actually needs it.
    ALLOWED_ORIGIN = "https://editor.provas.ic.unicamp.br"

    def set_default_headers(self):
        origin = self.request.headers.get("Origin")
        if origin == self.ALLOWED_ORIGIN:
            self.set_header("Access-Control-Allow-Origin", origin)
        self.set_header("Access-Control-Allow-Headers", "Content-Type, X-CMS-Authorization")
        self.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def options(self, *args, **kwargs):
        # The CORS preflight itself: Tornado's default for an unimplemented
        # method is 405, which browsers treat as "preflight failed" and
        # block the real request entirely, regardless of what it would have
        # returned. Deliberately undecorated (no @api_login_required etc.)
        # -- a preflight never carries the real request's auth header, so
        # requiring it here would make every preflight fail by construction.
        self.set_status(204)
        self.finish()
    # ranido-end


class ApiLoginHandler(ApiContestHandler):
    """Login handler.

    """
    @multi_contest
    def post(self):
        current_user = self.get_current_user()

        username = self.get_argument("username", "")
        password = self.get_argument("password", "")
        admin_token = self.get_argument("admin_token", "")

        if current_user is not None:
            if username != "" and current_user.user.username != username:
                self.json(
                    {"error": f"Logged in as {current_user.user.username} but trying to login as {username}"}, 400)
            else:
                cookie_name = self.contest.name + "_login"
                cookie = self.get_secure_cookie(cookie_name)
                self.json({"login_data": self.request.headers.get(
                    "X-CMS-Authorization", cookie if cookie is not None else "Already-Logged-In")})

            return

        try:
            # ranido-begin
            #logger.warning(f"[ApiLoginHandler] IP address provided by Tornado: {self.request.remote_ip}")
            # ranido-end
            ip_address = ipaddress.ip_address(self.request.remote_ip)
        except ValueError:
            logger.warning("[ApiLoginHandler] Invalid IP address provided by Tornado: %s",
                           self.request.remote_ip)
            return None

        participation, login_data = validate_login(
            self.sql_session, self.contest, self.timestamp, username, password,
            ip_address, admin_token=admin_token)

        if participation is None:
            self.json({"error": "Login failed"}, 403)
        elif login_data is not None:
            cookie_name = self.contest.name + "_login"
            self.json({"login_data": self.create_signed_value(
                cookie_name, login_data).decode()})
        else:
            self.json({})

    def check_xsrf_cookie(self):
        pass


class ApiTaskListHandler(ApiContestHandler):
    """Handler to list all tasks and their statements.

    """
    @api_login_required
    @actual_phase_required(0, 3)
    @multi_contest
    def get(self):
        contest = self.contest
        tasks = []
        for task in contest.tasks:
            if task.name in ("tarefa", "hashedName-d8724aa0b88f985f11"):
                continue
            name = task.name
            statements = [s for s in task.statements]
            sub_format = task.submission_format
            tasks.append({"name": name,
                          "statements": statements,
                          "submission_format": sub_format})
        self.json({"tasks": tasks})


class ApiSubmitHandler(ApiContestHandler):
    """Handles the received submissions.

    """
    @api_login_required
    @actual_phase_required(0, 3)
    @multi_contest
    def post(self, task_name: str):
        task = self.get_task(task_name)
        if task is None:
            self.json({"error": "Task not found"}, 404)
            return

        # Only set the official bit when the user can compete and we are not in
        # analysis mode.
        official = self.r_params["actual_phase"] == 0

        # If the submission is performed by the administrator acting on behalf
        # of a contestant, allow overriding.
        if self.impersonated_by_admin:
            try:
                official = self.get_boolean_argument('override_official', official)
                override_max_number = self.get_boolean_argument('override_max_number', False)
                override_min_interval = self.get_boolean_argument('override_min_interval', False)
            except ValueError as err:
                self.json({"error": str(err)}, 400)
                return
        else:
            override_max_number = False
            override_min_interval = False

        try:
            submission = accept_submission(
                self.sql_session, self.service.file_cacher, self.current_user,
                task, self.timestamp, self.request.files,
                self.get_argument("language", None), official,
                override_max_number=override_max_number,
                override_min_interval=override_min_interval,
            )
            self.sql_session.commit()
        except UnacceptableSubmission as e:
            logger.info("API submission rejected: `%s' - `%s'",
                        e.subject, e.formatted_text)
            self.json({"error": e.subject, "details": e.formatted_text}, 422)
        else:
            logger.info(
                f'API submission accepted: Submission ID {submission.id}')
            self.service.evaluation_service.new_submission(
                submission_id=submission.id)
            self.json({'id': str(submission.opaque_id)})

# ranido-begin
import tornado.web

from cms import config, FEEDBACK_LEVEL_FULL
from cms.db import UserTest, UserTestResult
from cms.grading.languagemanager import get_language
from cms.server import multi_contest
from cms.server.contest.submission import get_submission_count, \
    TestingNotAllowed, UnacceptableUserTest, accept_user_test
from cmscommon.mimetypes import get_type_for_file_name
from .contest import ContestHandler, FileHandler, api_login_required
from ..phase_management import actual_phase_required



class ApiTestHandler(ApiContestHandler):
    """Handles the received submissions.

    """
    @api_login_required
    @actual_phase_required(0, 3)
    @multi_contest
    def post(self, task_name):
        if not self.r_params["testing_enabled"]:
            raise tornado.web.HTTPError(404)

        task = self.get_task(task_name)
        if task is None:
            raise tornado.web.HTTPError(404)

        query_args = dict()

        try:
            user_test = accept_user_test(
                self.sql_session, self.service.file_cacher, self.current_user,
                task, self.timestamp, self.request.files,
                self.get_argument("language", None))
            self.sql_session.commit()
        except TestingNotAllowed:
            logger.warning("User %s tried to make test on task %s.",
                           self.current_user.user.username, task_name)
            raise tornado.web.HTTPError(404)
        except UnacceptableUserTest as e:
            logger.info("Sent error: `%s' - `%s'", e.subject, e.formatted_text)
            self.notify_error(e.subject, e.text, e.text_params)
        else:
            pass
            self.service.evaluation_service.new_user_test(user_test_id=user_test.id)
            logger.info(
                 f'API submission accepted: Submission ID {user_test.id}')
            self.json({'id': str(user_test.opaque_id)})


class ApiTestStatusHandler(ApiContestHandler):

    refresh_cookie = False

    @api_login_required
    @actual_phase_required(0)
    @multi_contest
    def get(self, task_name, opaque_id):
        if not self.r_params["testing_enabled"]:
            raise tornado.web.HTTPError(404)

        task = self.get_task(task_name)
        if task is None:
            raise tornado.web.HTTPError(404)

        user_test = self.do_get_user_test(task, opaque_id)
        if user_test is None:
            raise tornado.web.HTTPError(404)

        ur = user_test.get_result(task.active_dataset)
        data = dict()

        if ur is None:
            data["status"] = UserTestResult.COMPILING
        else:
            data["status"] = ur.get_status()

        if data["status"] == UserTestResult.COMPILING:
            data["status_text"] = self._("Compiling...")
        elif data["status"] == UserTestResult.COMPILATION_FAILED:
            data["status_text"] = self._("Compilation failed")
            data["compilation_stderr"] = ur.compilation_stderr
            data["compilation_stdout"] = ur.compilation_stdout
        elif data["status"] == UserTestResult.EVALUATING:
            data["status_text"] = self._("Executing...")
        elif data["status"] == UserTestResult.EVALUATED:

            data["status_text"] = ur.evaluation_text
            data["execution_stderr"] = ur.execution_stderr

            if ur.execution_time is not None:
                data["execution_time"] = \
                    self.translation.format_duration(ur.execution_time)
            else:
                data["execution_time"] = None

            if ur.execution_memory is not None:
                data["memory"] = \
                    self.translation.format_size(ur.execution_memory)
            else:
                data["memory"] = None

            digest = ur.output
            try:
                output = self.service.file_cacher.get_file_content(digest).decode('utf-8')
            except:
                output = ""
            data["output"] = output
            
        self.write(data)

# ranido-end

class ApiSubmissionListHandler(ApiContestHandler):
    """Retrieves the list of submissions on a task.

    """
    @api_login_required
    @actual_phase_required(0, 3)
    @multi_contest
    def get(self, task_name: str):
        task = self.get_task(task_name)
        if task is None:
            self.json({"error": "Not found"}, 404)
            return
        submissions: list[Submission] = (
            self.sql_session.query(Submission)
            .filter(Submission.participation == self.current_user)
            .filter(Submission.task == task)
            .all()
        )
        self.json({'list': [{"id": str(s.opaque_id)} for s in submissions]})

# ranido-begin
class ApiSubmissionStatusHandler(ApiContestHandler):
    """Polled by EditorOBI after a real submission (not a test) to show
    the per-subtask score breakdown inline, same shape/purpose as
    ApiTestStatusHandler above but for Submission/SubmissionResult instead
    of UserTest/UserTestResult. Reuses CMS's own score_type_object.get_html_details()
    (same call SubmissionDetailsHandler in tasksubmission.py makes) so the
    HTML/visibility rules (tokens, analysis mode, feedback_level) are
    exactly what CWS's own "Details" view would show this contestant --
    no separate scoring/visibility logic to keep in sync.

    """

    refresh_cookie = False

    @api_login_required
    @actual_phase_required(0, 1, 2, 3, 4)
    @multi_contest
    def get(self, task_name, opaque_id):
        task = self.get_task(task_name)
        if task is None:
            raise tornado.web.HTTPError(404)

        submission = self.get_submission(task, opaque_id)
        if submission is None:
            raise tornado.web.HTTPError(404)

        sr = submission.get_result(task.active_dataset)
        data = dict()

        if sr is None or not sr.compiled():
            data["status"] = "compiling"
        elif sr.compilation_failed():
            data["status"] = "compilation_failed"
            data["compilation_stdout"] = sr.compilation_stdout
            data["compilation_stderr"] = sr.compilation_stderr
        elif not sr.scored():
            data["status"] = "evaluating"
        else:
            data["status"] = "scored"
            # Same visibility rule SubmissionDetailsHandler uses: full
            # feedback only with a used token or during analysis mode,
            # public (subtask-limited per the task's own config) otherwise
            # -- matters beyond just Pratique's "unrestricted" use, since
            # this same endpoint would show real exam-time visibility
            # rules correctly if ever polled there too.
            is_analysis_mode = self.r_params["actual_phase"] == 3
            full_feedback = submission.tokened() or is_analysis_mode
            score_type = task.active_dataset.score_type_object
            raw_details = sr.score_details if full_feedback else sr.public_score_details
            feedback_level = FEEDBACK_LEVEL_FULL if is_analysis_mode else task.feedback_level
            data["score"] = sr.score if full_feedback else sr.public_score
            data["max_score"] = score_type.max_score if full_feedback else score_type.max_public_score
            data["details_html"] = score_type.get_html_details(
                raw_details, feedback_level, translation=self.translation)

        self.write(data)
# ranido-end
