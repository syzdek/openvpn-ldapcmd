
OpenVPN LDAP Command
====================


Contents
--------

   1. Disclaimer
   2. Maintainers
   3. Background
   4. Source Code
   5. Package Maintence Notes


Disclaimer
==========

   This software is provided by the copyright holders and contributors "as
   is" and any express or implied warranties, including, but not limited to,
   the implied warranties of merchantability and fitness for a particular
   purpose are disclaimed. In no event shall David M. Syzdek be liable for
   any direct, indirect, incidental, special, exemplary, or consequential
   damages (including, but not limited to, procurement of substitute goods or
   services; loss of use, data, or profits; or business interruption) however
   caused and on any theory of liability, whether in contract, strict
   liability, or tort (including negligence or otherwise) arising in any way
   out of the use of this software, even if advised of the possibility of
   such damage.


Software Requirements
=====================

   * OpenLDAP


Maintainers
===========

   David M. Syzdek
   david@syzdek.net


Source Code
===========

   The source code for this project is maintained using git
   (http://git-scm.com).  The following contains information to checkout the
   source code from the git repository.

   Browse Source:

      https://github.com/syzdek/openvpn-ldapcmd

   Git URLs:

      https://github.com/syzdek/openvpn-ldapcmd.git
      git@github.com:syzdek/openvpn-ldapcmd.git

   Downloading Source:

      $ git clone https://github.com/syzdek/openvpn-ldapcmd.git

   Preparing Source:

      $ cd openvpn-ldapcmd
      $ ./autogen.sh

   Git Branches:

      master - Current release of packages.
      next   - changes staged for next release
      pu     - proposed updates for next release
      xx/yy+ - branch for testing new changes before merging to 'pu' branch


Package Maintence Notes
=======================

   This is a collection of notes for developers to use when maintaining this
   package.

   New Release Checklist:

      - Switch to 'master' branch in Git repository.
      - Update version in configure.ac.
      - Update date and version in ChangeLog.
      - Commit configure.ac and ChangeLog changes to repository.
      - Create tag in git repository:
           $ git tag -s v${MAJOR}.${MINOR}
      - Push repository to publishing server:
           $ git push --tags origin master:master next:next pu:pu

   Creating Source Distribution Archives:

      $ ./configure
      $ make update
      $ make distcheck
      $ make dist-bzip2

