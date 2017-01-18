#!/bin/bash
#
#   OpenVPN LDAP Command
#   Copyright (C) 2017 David M. Syzdek <david@syzdek.net>.
#
#   @SYZDEK_BSD_LICENSE_START@
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#      * Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#      * Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#      * Neither the name of David M. Syzdek nor the
#        names of its contributors may be used to endorse or promote products
#        derived from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
#   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
#   PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL DAVID M. SYZDEK BE LIABLE FOR
#   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#   SUCH DAMAGE.
#
#   @SYZDEK_BSD_LICENSE_END@
#

if test ${#} != 3;then
   echo "Usage: $(basename "${0}") <infile> <outfile> <name>"
   exit 1
fi
INFILE="${1}"
OUTFILE="${2}"
SCHEMANAME="${3}"
SRCFILE=$(basename "${INFILE}")


if test ! -f "${INFILE}";then
   echo "$(basename "${0}"): ${INFILE}: does not exist"
   exit 1
fi


grep '^##' "${INFILE}" > "${OUTFILE}"
cat << EOF >> "${OUTFILE}"
#
#   This file was automatically generated from $SRCFILE;
#   see that file for complete references.
#
dn: cn=${SCHEMANAME},cn=schema,cn=config
objectClass: olcSchemaConfig
cn: $SCHEMANAME
EOF


perl -p0e 's/\n //g' ${INFILE}  \
   |sed \
       -e 's/ \{2,\}/ /g' \
       -e 's/^[aA][tT][tT][rR][iI][bB][uU][tT][eE][tT][yY][pP][eE] /olcAttributeTypes: /g' \
       -e 's/^[oO][bB][jJ][eE][cC][tT][cC][lL][aA][sS][sS] /olcObjectClasses: /g' \
   |egrep -v '^#|^$' \
   |awk 'length > 78 { while ( length($0) > 78 ) { printf "%s\n ", substr($0,1,78); $0 = substr($0,79) } if (length) print; next } {print}' \
   >> "${OUTFILE}"


# end of script
