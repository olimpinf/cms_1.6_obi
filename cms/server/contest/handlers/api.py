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
            ip_address = ipaddress.ip_address(self.request.remote_ip)
        except ValueError:
            logger.warning("Invalid IP address provided by Tornado: %s",
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

from cms import config
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
        logger.warning('API submission received')
        logger.warning(f'language: {self.get_argument("language", None)}')

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

        # ranido-begin
        #if ur.stderr_txt is not None:
        #    data["stderr_txt"] = ur.stderr_txt
        #else:
        #    data["stderr_txt"] = None
        data["execution_stderr"] = "Um erro, fixo, rever"
        
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
