// Copyright 2018 Zurich University of Applied Sciences.
// All rights reserved. Use of this source code is governed
// by a BSD-style license that can be found in the LICENSE file.

/*

Mkjson extracts PTO3 metadata information from raw tracebox files.

It assumes that the tracebox files are part of a campaign (not
necessarily all in the same campaign), and that suitable metadata
for that campaign includes the filetype and the owner of these
raw data files, for example (examples are actually NDJSON, but
for readability, we will pretty-print them):

	{
		"_file_type": "tracebox-v1-ndjson",
		"_owner": "sten@artdecode.de"
	}

A typical use for mkmeta is a directory full of tracebox NDJSON files.
There you would run:

	mkmeta -owner owner-name [-with-campaign] *.json

The result would be, (1) for every tracebox file a.json, a file
a.pto_file_metadata.json; and, if the -with-cmpaign flag was also
given, a file __pto_campaign_metadata.json with the file type and
the owner. A typical file metadata file might look as follows:

	{
		"src_ip": "128.10.18.52",
		"dst_tcp_port": 80,
		"_time_start": "2016-03-02T13:58:34Z",
		"_time_end":"2016-03-04T15:01:08Z"
	}

This means that the contents of the tracebox file was created from
the source IP 128.10.18.52 to the destination port 80, and that
measurements last from 2016-03-02T13:58:34Z to 2016-03-04T15:01:08Z.

The source IP and port number are extracted from the tracebox file
name, which must have the form

	<port>-<num>-<src_ip>.json

where <src_ip> is an IPv4 address in dotted-quad notation. The program
will log an error if the file name does not have this format, and no
metadata file will be written.
*/
package main
