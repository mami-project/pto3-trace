// Copyright 2018 Zurich University of Applied Sciences.
// All rights reserved. Use of this source code is governed
// by a BSD-style license that can be found in the LICENSE file.

/*

Tb-cond goes through tracebox files looking for candidates for PTO conditions.

Tracebox files contain lines that note changes, additions from, and deletions
to IP and TCP headers. What exactly changed is captured in name-value pairs
where the names look like IP:TTL or TCP::SeqNumber. This program looks
through all the files on the command line and collects, counts, and sorts those
names. An example output might be:

     5412080 IP::TTL
     5412080 IP::Checksum
     2845976 IP::DiffServicesCP
       35282 TCP::O::MSS
        7806 TCP::Checksum
         796 TCP::O::SACKPermitted
         302 IP::Length
         250 IP::ID
         235 TCP::SeqNumber
          81 TCP::O::WSOPT-WindowScale
          72 TCP::Window
          50 TCP::Offset
          42 TCP::O::TSOPT-TimeStampOption
          13 TCP::Flags
          10 IP::ECN
           6 TCP::UrgentPtr
           6 TCP::Reserved
           3 TCP::O::Echo
           3 TCP::O::Quick-StartResponse
           2 TCP::O::PartialOrderConnectionPermitted
           2 TCP::O::TCPAuthenticationOption
           2 TCP::O::PartialOrderServiceProfile
           1 TCP::O::CC.ECHO
           1 TCP::O::SelectiveNegativeAck
           1 TCP::O::EchoReply

In order to speed up operations, this program uses workers that look through files
in parallel.

Usage:

	tb-cond [-workers n] file...

	-workers n	use n workers (default 1)
*/
package main
