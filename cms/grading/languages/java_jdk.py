#!/usr/bin/env python3

# Contest Management System - http://cms-dev.github.io/
# Copyright © 2016-2017 Stefano Maggiolo <s.maggiolo@gmail.com>
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

"""Java programming language definition, using the default JDK installed
in the system.

"""

import os

from shlex import quote as shell_quote

from cms.grading import Language


__all__ = ["JavaJDK"]


# ranido-begin
# OBI/Pratique task names look like "2021f3pj_ogro": they start with a
# digit, which is illegal as the start of a Java identifier. javac requires
# the public class to be named after the source file, so a submission
# compiled under the literal task name (e.g. "2021f3pj_ogro.java") can
# never compile, for any task here.
#
# When enabled, every Java submission is instead compiled and run under a
# single fixed class/file name (OBI_JAVA_CLASS_NAME below), regardless of
# the task -- the same scheme used by the previous OBI CMS. Contestants are
# expected to name their public class accordingly.
#
# Real exam CMS instances use short, non-numeric task names (e.g. "ogro",
# not "2021f3pj_ogro") and don't hit this problem at all, so they don't
# need this and must NOT have it enabled -- a submission there is expected
# to compile under its own task's name, not a fixed one. This is a
# Pratique-only workaround, since this source file is shared with real
# exam deployments: keep this False here (the git-tracked default, safe
# for any deployment), and only set it True in Pratique's own deployed
# copy of this file (not git-tracked). Do not change this default without
# updating pratique's live copy to match.
OBI_RENAME_JAVA_CLASS_FROM_TASK_NAME = False
OBI_JAVA_CLASS_NAME = "solucao"
# ranido-end


class JavaJDK(Language):
    """This defines the Java programming language, compiled and executed using
    the Java Development Kit available in the system.

    """

    USE_JAR = True

    @property
    def name(self):
        """See Language.name."""
        return "Java / JDK"

    @property
    def source_extensions(self):
        """See Language.source_extensions."""
        return [".java"]

    @property
    def executable_extension(self):
        """See Language.executable_extension."""
        return ".jar" if JavaJDK.USE_JAR else ".zip"

    @property
    def requires_multithreading(self):
        """See Language.requires_multithreading."""
        return True

    def get_compilation_commands(self,
                                 source_filenames, executable_filename,
                                 for_evaluation=True):
        """See Language.get_compilation_commands."""
        # ranido-begin
        copy_command = None
        if OBI_RENAME_JAVA_CLASS_FROM_TASK_NAME:
            task_source = source_filenames[0]
            ext = os.path.splitext(task_source)[1]
            renamed_source = OBI_JAVA_CLASS_NAME + ext
            if renamed_source != task_source:
                copy_command = ["/bin/cp", task_source, renamed_source]
                source_filenames = [renamed_source]
        # ranido-end

        compile_command = ["/usr/bin/javac"] + source_filenames
        # We need to let the shell expand *.class as javac create
        # a class file for each inner class.
        if JavaJDK.USE_JAR:
            jar_command = ["/bin/sh", "-c",
                           " ".join(["jar", "cf",
                                     shell_quote(executable_filename),
                                     "*.class"])]
            commands = [compile_command, jar_command]
        else:
            zip_command = ["/bin/sh", "-c",
                           " ".join(["zip",
                                     shell_quote(executable_filename),
                                     "*.class"])]
            commands = [compile_command, zip_command]

        # ranido-begin
        if copy_command is not None:
            commands = [copy_command] + commands
        # ranido-end
        return commands

    def get_evaluation_commands(
            self, executable_filename, main=None, args=None):
        """See Language.get_evaluation_commands."""
        args = args if args is not None else []

        # ranido-begin
        if OBI_RENAME_JAVA_CLASS_FROM_TASK_NAME:
            main = OBI_JAVA_CLASS_NAME
        # ranido-end

        if JavaJDK.USE_JAR:
            # executable_filename is a jar file, main is the name of
            # the main java class
            return [["/usr/bin/java", "-Deval=true", "-Xmx512M", "-Xss64M",
                     "-cp", executable_filename, main] + args]
        else:
            unzip_command = ["/usr/bin/unzip", executable_filename]
            command = ["/usr/bin/java", "-Deval=true", "-Xmx512M", "-Xss64M",
                       main] + args
            return [unzip_command, command]
