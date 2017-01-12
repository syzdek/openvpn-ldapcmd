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

openvpn_ldapcmd_setup()
{
   if test "x${OPENVPN_LDAPCMD_SETUP}" == "xyes";then
      return 0
   fi
   export OPENVPN_LDAPCMD_SETUP=yes
   export config=/etc/openvpn/openvpn.ovpn
   export daemon=1
   export daemon_log_redirect=0
   export daemon_pid=24764
   export daemon_start_time=$(($(date +%s)-3600))
   export dev=ovpn
   export dev_type=tun
   export ifconfig_broadcast=10.0.48.223
   export ifconfig_ipv6_local=2001:4948:d:1194::1
   export ifconfig_ipv6_netbits=64
   export ifconfig_ipv6_remote=2001:4948:d:1194::2
   export ifconfig_local=10.0.48.193
   export ifconfig_netmask=255.255.255.224
   export link_mtu=1621
   export local_1=107.152.127.18
   export local_port_1=1194
   export proto_1=udp
   export redirect_gateway=0
   export remote_port_1=1194
   export script_context=init
   export tun_mtu=1500
   export untrusted_ip=107.152.127.19
   export untrusted_port=35874
   export verb=3
}

# end of bash profile