tcpunmask
=========

tcpunmask - Attempt to unmask sanitized data from a TCP/IP packet
The last "stable" release was committed on Oct 13, 2013. There are still some significant bugs

SYNOPSIS
=========
tcpdump [ -vhdtbg ] [ -o filename ] packetdata

DESCRIPTION
=========
tcpunmask takes a packet as input in ASCII-Hex format. Sanitized nibbles are formatted as ?'s. tcpunmask will attempt every possibly data value in place of these unknown nibbles and check to see if the checksum(s) match the ones reported in the packet data. Becuase of this, this script will not function if the checksums are also sanitized.

When finished, tcpmask will report all valid packets based on checksum matches. The report is displayed with values seperated by commas; this way you can redirect stdout to a csv file for further filtering

OPTIONS
=========
	-v	Verbose. While brute forcing, this will display each packet that is currently being attempted, along with the calculated IP & TCP checksums
	-h	Help. Displays this dialog
	-d	Debug. Because I haven't looked at 'perl -d' yet, So I go old school and use liberal 'print' statements here and there (only executed with -d)
	-t	This is for performance debugging, it will give me the time spent for each subroutine, the main program, and total.
	-b	Bogon Be-gone. With this enabled, current bogons will be filtered out of results (https://www.team-cymru.org/Services/Bogons/)
	-o	Output. In the format of '-o results.csv'. Since output is already comma seperated, .csv makes sense
	-g	GeoIP. This adds another 'column' to our results; correlating GeoIP data with each packet, based on IP addresses

EXAMPLES
=========
	We are guessing the last 2 octets of the Source IP Address, we would also like verbose mode
	tcpunmask.pl -v 45000034001c4000400624a40a00????0a00010301bdc0bc984c4d618fb480cd8011038998DC00000101080a0bb24d88317a80f4
