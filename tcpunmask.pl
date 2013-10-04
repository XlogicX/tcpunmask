#!/usr/bin/perl
#TCP Unmask is a tool that attempts to recover sanitized data from an IP header (hopefully TCP as well). It is able to do this when people forget to also sanitize their checksums.
use warnings;
use strict;
use Getopt::Std;
use Time::HiRes;
use LWP::UserAgent;		#This is for bogons and geoIP data
##Whishlist
	#Make outputs more granular / more better (low priority)
	#Add GeoIP datas	(medium priority)
	#Cross reference bogons		(high priority)
	#Add --options to reduce invalid fields	(medium priority)
		#only ipv4
		#ip header length below 20 is invalid
		#etc...

my $start = Time::HiRes::time();	#Stores when the script started
my %options=();						#For cli options
getopts("dhvtb", \%options);			#Get the options passed
help() if defined $options{h};
my $debug = 0;						#A flag for the -d option
$debug = 1 if defined $options{d};
my @results;				#Container for where we store the results of bruteforcing
my $result_line;		#This is a container of just a single line for @results array
my $data = shift @ARGV;	#Get the input TCP/IP header (starting at IP header data)
if (!$data) {
	print "\nYou didn't enter a packet, here's help\n\n";
	help();
}
my @performance = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);	#Array to hold time values of how long each sub-routine takes (init to 0 for the routines not run)
my $bogons = bogonreq() if defined $options{b};				#Get bogons from Cymru

###############SubRoutines################

#Get rid of newlines and whitespace
sub blackspace($) {
	my $begin = Time::HiRes::time();	#Get start time of sub
   	my $header = shift;					#Get data passed to our sub
	$header =~ s/\s|\n//g;				#find all whitespace and newlines and replace it with nothing
	my $end = Time::HiRes::time();		#Get finish time
	$performance[0] += ($end-$begin);	#Add to total time for this sub
	return $header;						#Return our results
}

#Calculate checksum given IP header info
sub checksum($){
	my $begin = Time::HiRes::time();						#Get start time of sub
	my $sum = shift;										#Get our header info passed to this sub
	my $length;												#Create container for IP length
	if ($sum =~ /^.(.)/) { 									#Parse out the 2nd nibble (IP length)
		$length = hex($1);									#Hex->Decimal conversion of it
		print "header length hex: $length\n" if $debug;			#(debug): give me the header length
		$length *= 4;										#Multiply by 4 (it's an IP thing)
		$length = ($length * 2) - 24;						#length no longer length, but offset for how much data AFTER checksum
		print "header length offset: $length\n" if $debug;		#(debug): in the case we want to know that offset
	}
	$sum =~ s/^(\w{20})....(.{$length}).*/$1$2/;			#Get rid of checksum bytes
	print "data without checksum: $sum\n" if $debug;			#(debug): see what header looks like without checksum

	#Get 2byte words for all header data (to sum)
	my $i = 0;						#init the loop cntr
	my @words;						#array for 2-byte words for adding
	while ($sum) {					#while there is still data in our remaining header data
		if ($sum =~ /^(.{4})/) {	#parse out the first 4 characters (nibbles) (2-bytes)
			$words[$i] = $1;		#add it to our array
		$sum =~ s/^.{4}//;			#remove it from $sum
		}
		$i++;						#inc the cntr for next 2-bytes (until done)
	}

	#Add all the 2-byte values up
	my $wordcount = @words;			#how many values are we adding? (unknown due to IP options)
	$i = 0;							#init the loop cntr
	$sum = 0;						#init our total
	while ($i < $wordcount) {		#keep adding until we've added all of the words
		$sum += hex($words[$i]);	#add a decimal form of our ASCII-Hex 2-bytes
		$i++;						#inc the cntr for next 2-bytes to add
	}

	#Determine what value overflowed into carry (past 2 bytes)
	my $hexsum = sprintf("%.4X\n", $sum);	#Just get the Least Significant nibbles
	my $carry;								#create container for value of carry
	if ($hexsum =~ /(.).{4}/) {				#if there are 5 nibbles, parse the Most Significant nibble
		$carry = $1;						#store it as the carry
	} else {								#otherwise
		$carry = 0;								#it's zero
	}

	#Now add the carry to the non-overflowed sum
	$sum += $carry;						#add the carry to the non-overflowed sum		
	$sum = sprintf("%.4X\n", $sum);		#Re-ASCII-hex it
	if ($sum =~ /.(.{4})/) {			#Regex to lop off the carry part
		$sum = $1;
	}

	$sum =~ tr/0123456789ABCDEF/FEDCBA9876543210/;	#mathemetically equiv to FFFF-$sum or 1's compliment

	print "ip_checksum: $sum\n" if $debug;	#(debug): Reports the resulting checksum

	my $end = Time::HiRes::time();			#Get finish time
	$performance[1] += ($end-$begin);		#Add to total time for this sub

	return $sum;							#Return the resulting checksum
}

#Gets the checksum reported by IP header (not calculated)
sub getsum($) {
	my $begin = Time::HiRes::time();	#Get start time of sub
	my $sum = shift;					#Get header info passed to this sub
	$sum =~ s/^.{20}(....).+$/$1/;		#Parse checksum bytes
	my $end = Time::HiRes::time();		#Get finish time
	$performance[2] += ($end-$begin);	#Add to total time for this sub
	return $sum;						#Return the checksum reported by original IP header
}

#Calculate checksum given TCP header info
sub checksumtcp($){
	my $begin = Time::HiRes::time();				#Get start time of sub
	my $sum = shift;								#grab packet data passed to this sub
	my $offset = offset($sum);						#Get's size of IP header (assuming ASCII hex format)
	my $saddr;										#Container for source address
	my $daddr;										#Container for destination address
	my $saddr1;										#Container for first half of source address
	my $saddr2;										#Container for last half of source address
	my $daddr1;										#Container for first half of destination address
	my $daddr2;										#Container for last half of destination address
	my $tlength;									#Container for length of packet (as reported by IP header)
	my $tcplength;									#Container for length of just tcp data (header & data)
	my $offsetz = $offset - 16;						#amount of values just before IP addresses

	#Populate some vars
	if ($sum =~ /^.{$offsetz}(.{8})(.{8}).*/) {		#Populate Source and Destination IP's
		$saddr = $1;
		$daddr = $2;
	}
	if ($sum =~ /^.{4}(.{4}).+/) {					#Parse packet length (as reported by IP header)
		$tlength = hex($1);							#Get the decimal value into $tlength
	}
	$tcplength = $tlength - ($offset/2);			#TCP header + data = total packet length
	$tcplength = sprintf("%.4X\n", $tcplength);		#Get ASCII-hex representation of this
	chomp($tcplength);								#chomp chomp chomp for safe measure
	my $tcp_data = $sum;							#Get full headers info into $tcp_data (it's both IP and TCP for now though...)
	$tcp_data =~ s/^.{$offset}(.*)/$1/;				#Parse out the IP data leaving just TCP
	my $tcp_without_sum = $tcp_data;				#Store TCP data in $tcp_without_sum var to process next
	$tcp_without_sum =~ s/^(.{32}).{4}(.+)/$1$2/;	#Parse out the checksum

	#Get 2byte words for all header data (to sum)
	my $i = 0;									#init the loop cntr
	my @words;									#Container of array of 2-byte words to sum
	while ($tcp_without_sum) {					#while we still have 2-byte words
		if ($tcp_without_sum =~ /^(.{4})/) {	#Get the first 2 bytes
			$words[$i] = $1;					#store them in the words array			
		$tcp_without_sum =~ s/^.{4}//;			#remove those 2 bytes from $tcp_without_sum
		}
		$i++;									#On to the next 2 bytes
	}
	if ($saddr =~ /(.{4})(.{4})/) {				#Use some regex to split IP's into 2-byte halves
		$saddr1 = $1;
		$saddr2 = $2;
	}
	if ($daddr =~ /(.{4})(.{4})/) {
		$daddr1 = $1;
		$daddr2 = $2;
	}
	@words = (@words, '0006', $saddr1, $saddr2, $daddr1, $daddr2, $tcplength);	#array of all 2-byte words to add

	#Add the words
	my $wordcount = @words;			#how many words
	$i = 0;							#init the loop cntr
	$sum = 0;						#init our sum
	while ($i < $wordcount) {		#while we still have words to add
		$sum += hex($words[$i]);	#add current word to $sum
		$i++;						#On to next word
	}

	#Determine what value overflowed into carry (past 2 bytes)
	my $hexsum = sprintf("%.4X\n", $sum);	#Just get the Least Significant nibbles
	my $carry;								#create container for value of carry
	if ($hexsum =~ /(.).{4}/) {				#if there are 5 nibbles, parse the Most Significant nibble
		$carry = $1;						#store it as the carry
	} else {								#otherwise
		$carry = 0;							#it's zero
	}

	#Now add the carry to the non-overflowed sum
	$sum += $carry;						#add the carry to the non-overflowed sum
	$sum = sprintf("%.4X\n", $sum);		#Re-ASCII-hex it
	if ($sum =~ /.(.{4})/) {			#Regex to lop off the carry part
		$sum = $1;
	}

	$sum =~ tr/0123456789ABCDEF/FEDCBA9876543210/;	#mathemetically equiv to FFFF-$sum or 1's compliment

	print "tcp_checksum: $sum\n" if $debug;			#(debug): Reports the resulting checksum

	my $end = Time::HiRes::time();		#Get finish time
	$performance[3] += ($end-$begin);	#Add to total time for this sub

	return $sum;	#Return the checksum
}

#Gets the checksum reported by TCP header (not calculated)
sub getsumtcp($) {
	#I will eventually have to do a sanity check with the IP header length (when that nibble is an unknown)
	my $begin = Time::HiRes::time();			#Get start time of sub
	my $sum = shift;							#get header data passed to this sub
	my $offset = offset($sum);					#get IP header offset (not static, due to IP options)
	$sum =~ s/^.{$offset}.{32}(....).*/$1/;		#Parse checksum bytes
	my $end = Time::HiRes::time();				#Get finish time
	$performance[4] += ($end-$begin);			#Add to total time for this sub
	return $sum;								#Return the checksum reported by original IP header
}

#Get comma seperated list of offsets where ?'s are found
sub get_unknown($) {
	#This function could be overkill for what I'm doing. I initially wanted to know the position of each ?,
	#I don't think I currently need that info, but I still use this function for some of the artifacts that
	#it produces
	my $begin = Time::HiRes::time();	#Get start time of sub
	my $header = shift;					#Get header data passed to this sub
	my $offset = offset($header);		#Get the length of IP heaader
	$header =~ s/^(.{$offset}).*/$1/;	#Get just the IP header parsed out
	my @nibbles = split('',$header);	#Store each char in an array called @nibbles
	my $nibblecount = @nibbles;			#Count how many chars (jeeze, could be derived from offset...)

	#Get a Scalar "CSV" string of the location of each '?' char
	my $i = 0;												#init the loop cntr
	my $questions = "";										#init $questions var
	while ($i < $nibblecount) {								#For all of our nibbles
		$questions .= ',' . $i if ($nibbles[$i] eq '?');	#add array offset to your scaler csv offset list
		$i++;												#On to the next
	}
	$questions =~ s/^,//;									#Remove the first comma

	my $end = Time::HiRes::time();							#Get finish time
	$performance[5] += ($end-$begin);						#Add to total time for this sub

	return $questions;										#Return our scalar csv line of where each ? is
}

#Get comma seperated list of offsets where ?'s are found
sub get_unknown_tcp($) {
	#See get_unknown() about how I feel about the relevance of this sub
	my $begin = Time::HiRes::time();	#Get start time of sub
	my $header = shift;					#Get header data passed to this sub
	my $offset = offset($header);		#Get the length of IP header
	$header =~ s/^.{$offset}(.*)/$1/;	#Parse out just the TCP side of this
	my @nibbles = split('',$header);	#Store each char in an array called @nibbles
	my $nibblecount = @nibbles;			#Count how many chars

	#Get a Scalar "CSV" string of the lcation of each '?' char
	my $i = 0;												#init the loop cntr
	my $questions = "";										#init $questions var
	while ($i < $nibblecount) {								#For all of our nibbles
		$questions .= ',' . $i if ($nibbles[$i] eq '?');	#add array offset to your scaler csv offset list
		$i++;												#On to the next
	}
	$questions =~ s/^,//;									#Remove the first comma

	my $end = Time::HiRes::time();							#Get finish time
	$performance[6] += ($end-$begin);						#Add to total time for this sub

	return $questions;										#Return our scalar csv line of where each ? is
}

#Just parse out the IP header and return it
sub get_ipdata{
	my $begin = Time::HiRes::time();		#Get start time of sub
	my $ip_data = shift;					#Get full header data passed to this sub
	my $offset = offset($ip_data);			#get the offset
	if ($ip_data =~ /^(.{$offset}).*/) {	#Parse the IP part of packet
		$ip_data = $1;						#store it
	}
	my $end = Time::HiRes::time();			#Get finish time
	$performance[7] += ($end-$begin);		#Add to total time for this sub
	return $ip_data;						#return it
}

#Just parse out the TCP header and return it
sub get_tcpdata{
	my $begin = Time::HiRes::time();	#Get start time of sub
	my $tcp_data = shift;					#Get full header data passed to this sub
	my $offset = offset($tcp_data);			#get the offset
	if ($tcp_data =~ /^.{$offset}(.*)$/) {	#Parse the TCP part of packet
		$tcp_data = $1;						#store it
	}
	my $end = Time::HiRes::time();			#Get finish time
	$performance[8] += ($end-$begin);		#Add to total time for this sub
	return $tcp_data;						#return it
}

sub offset {
	my $begin = Time::HiRes::time();	#Get start time of sub
	my $sum = shift;			#Get header data passed to sub
	my $offset;					#Container for the offset
	if ($sum =~ /^.(.)/) {		#Parse out the second nibble
		$offset = $1;			#store it
		$offset *= 8;			#offset nibble times 4 (bytes) (but * 8 becuase each nibble is a character)
	}
	my $end = Time::HiRes::time();		#Get finish time
	$performance[9] += ($end-$begin);	#Add to total time for this sub
	return $offset;						#Return the formatted offset
}

#ASCII HEX encodes the brute-forcing part of our packet
sub asciihex {
	my $begin = Time::HiRes::time();	#Get start time of sub
	my $hexstring = $_[0];									#This is the bruteforce iteration
	my $nibbles = $_[1];									#This is how many characters total to brute
	$hexstring = sprintf("%.${nibbles}X\n", $hexstring);	#This ASCIIfies the brute force value
	my $end = Time::HiRes::time();							#Get finish time
	$performance[10] += ($end-$begin);						#Add to total time for this sub
	return $hexstring;										#This returns it
	#For example, say we were on $try 50 ($hexstring), and were guessing through 4 characters ($nibbles)
	#	$hexstring = 50
	#	$nibbles = 4
	#	$hextring would = 0032 (This is hex for 50)
}

#Creates a bruteforce guess with full packet
sub createguess {
	#Get params
	my $begin = Time::HiRes::time();	#Get start time of sub
	my $data = $_[0];					#Our header with ?'s
	my $try = $_[1];					#Our brute-force replacement for the ?'s

	my @trys = split('',$try);	#make each guess nibble seperate
	my $nibbles = @trys;		#make note of now many nibbles there are

	#Craft packet replacing ?'s with our current brute force value
	my $i = 0;						#init the loop cntr
	while ($i < $nibbles) {			#while we still have nibbles to replace
		$data =~ s/\?/$trys[$i]/;	#Replace the first available ? with current nibble in our brute array
		$i++;						#Inc the brute nibble, on to the next ?
	}

	my $end = Time::HiRes::time();				#Get finish time
	$performance[11] += ($end-$begin);			#Add to total time for this sub

	return $data;	#Return our packet with no ?'s
}

#Routine for formatting output results in "english"
sub display {
	my $begin = Time::HiRes::time();	#Get start time of sub
	my $data = shift;				#Get header info, this is specifically IP header data
	$result_line = "";				#init the "CSV" result line for this packet
	my ($ipver,$headl,$tos,$tl,$id,$frag,$ttl,$prot,$sum,$saddr, $daddr, $options);	#Declare containers
	if ($data =~ /(.)(.)(..)(....)(....)(....)(..)(..)(....)(.{8})(.{8})(.*)/) {	#Parse all the fields
		$ipver = $1;
		$headl = $2;
		$tos = $3;
		$tl = $4;
		$id = $5;
		$frag = $6;
		$ttl = $7;
		$prot = $8;
		$sum = $9;
		$saddr = $10;
		$daddr = $11;
		$options = $12 if (($12) && ($headl ne 5));	#If there are options, print them raw (only if header length is greater than 20)
	}
	#Add Ipversion, header length, TOS, IP-ID, Fragment, Protocol Type, and Checksum to $result_line
	$result_line .= hex($ipver) . "," . $headl * 4 . "," . "$tos," . hex($tl) . "," . "$id," . "$frag," . hex($ttl) . "," . "$prot," . "$sum,";
	display_ip($saddr);							#Add Source address to result line
	$result_line .= ",";						#Add the comma seperator
	display_ip($daddr);							#Add Destination address to result line
	$result_line .= ",$options" if $options;	#If there are options, add a comma and the options
	$result_line .= "\n";						#Regardless, newline it to prepare for next row of csv
	@results = (@results, $result_line);		#Add this line to our total @results CSV format

	my $end = Time::HiRes::time();				#Get finish time
	$performance[12] += ($end-$begin);			#Add to total time for this sub
}

#Co-routine for the display sub, for formatting IP addresses
sub display_ip {
	my $begin = Time::HiRes::time();		#Get start time of sub
	my $ip = shift;							#Take the IP
	if ($ip =~ /(..)(..)(..)(..)/) {		#Get its octets
		#Format it in a decimal dot notation and add it to our $result_line CSV format
		$result_line .= hex($1) . "." . hex($2) . "." . hex($3) . "." . hex($4);
	}
	my $end = Time::HiRes::time();			#Get finish time
	$performance[13] += ($end-$begin);		#Add to total time for this sub
}

sub display_tcp {
	my $begin = Time::HiRes::time();	#Get start time of sub

	my $data = shift;					#Get packet
	display($data);						#Print the IP stuff
	$result_line = "";				#init the "CSV" result line for this packet
	my $tcp_data = get_tcpdata($data);	#Isolate out TCP data
	$results[-1] =~ s/\n$/,/;			#replace the newline in our IP row with a comma instead (since we now realize we are not done with the line)

	my ($sport, $dport, $seq, $ack, $offset, $res, $flags, $window, $checksum, $urg, $dataz);	#Declare containers
	if ($tcp_data =~ /(.{4})(.{4})(.{8})(.{8})(.)(.)(.{4})(.{4})(.{4})(.*)/) {	#Parse all the fields
		$sport = $1;
		$dport = $2;
		$seq = $3;
		$ack = $4;
		$offset = $5;
		$res = $6;
		$window = $7;
		$checksum = $8;
		$urg = $9;
		$dataz = $10 if ($10);	#If there's data, lets get that

	}

	$result_line .= hex($sport) . "," . hex($dport) . "," . hex($seq) . "," . hex($ack) . "," . hex($offset * 4) . "," . $res . "," . $window . "," . $checksum . "," . $urg;
	$result_line .= ",$dataz" if $dataz;
	$result_line .= "\n";
	@results = (@results, $result_line);	#Add the TCP data to it

	my $end = Time::HiRes::time();				#Get finish time
	$performance[15] += ($end-$begin);			#Add to total time for this sub
}

#Sub for correlating results with geoip data
sub geo {
	#This is a stub for now
	my $begin = Time::HiRes::time();	#Get start time of sub
	open IN, 'GeoLiteCity-Blocks.csv' or die "The file has to actually exist, try again $!\n";	#input filehandle is IN

	close IN;
	my $end = Time::HiRes::time();							#Get finish time
	$performance[14] += ($end-$begin);						#Add to total time for this sub
}

sub bogonreq {
	my $begin = Time::HiRes::time();	#Get start time of sub
	my $ua = LWP::UserAgent->new;	#$ua is our web object
	my $response = $ua->get('http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt');
	if ($response->is_success) {
		$response = $response->decoded_content;  # or whatever
	} else {
		die $response->status_line;
	}
	my $end = Time::HiRes::time();			#Get finish time
	$performance[16] += ($end-$begin);		#Add to total time for this sub
	return $response;
}

sub bogon {
	#https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt
	my $begin = Time::HiRes::time();	#Get start time of sub
	my $packet = shift;					#Get packet
	my $response = $bogons;

	#Get Source and Dest IP's (in decimal form)
	my ($source, $dest);
	if ($packet =~ /^.{24}(.{8})(.{8})/) {
		$source = hex($1);
		$dest = hex($2);
	}

	#Gotta make a better data structure for CIDR IP's
	my @networks = split("\n", $response);	#Get each CIDR line
	splice (@networks, 0, 1);				#Get rid of first line, of which is a comment
	my $i = 0;									#just a loop cntr
	foreach (@networks) {
		my $network = $_;
		if (($network ne '10.0.0.0/8') && ($network ne '10.0.0.0/8') && ($network ne '10.0.0.0/8')){
			my $cidr;
			my $range;
			if ($network =~ /(.+?)\/(\d+)/) {
				$cidr = $2;
				my $start = $1;
				if ($start =~ /(\d+?)\.(\d+?)\.(\d+?)\.(\d+?)/) {
					$start = ($1 * 16777216) + ($2 * 65536) + ($3 * 256) + $4;
				}
				my $end = ($start + ((2 ** (32 - $cidr)) - 1));

				if (($source > $start) && ($source < $end)) {
					#print "Source is a bogon\n";
					return 'bogon';
				}
				if (($dest > $start) && ($dest < $end)) {
					#print "Dest is a bogon\n";
					return 'bogon';
				}

				$range = "$start,$end";
			} else {
				$range = $network;
			}
			$networks[$i] = $range;
			$i++;
		}
	}
	my $end = Time::HiRes::time();			#Get finish time
	$performance[17] += ($end-$begin);		#Add to total time for this sub
}

#Routine for displaying detailed subroutine performance
sub perf {
	print "Subroutine Performance:\n";
	print "\tblackspace(): $performance[0]\n";
	print "\tchecksum(): $performance[1]\n";
	print "\tgetsum(): $performance[2]\n";
	print "\tchecksumtcp(): $performance[3]\n";
	print "\tgetsumtcp(): $performance[4]\n";
	print "\tget_unknwon(): $performance[5]\n";
	print "\tget_unknown_tcp(): $performance[6]\n";
	print "\tget_ipdata(): $performance[7]\n";
	print "\tget_tcpdata(): $performance[8]\n";
	print "\toffset(): $performance[9]\n";
	print "\tasciihex(): $performance[10]\n";
	print "\tcreateguess(): $performance[11]\n";
	print "\tdisplay(): $performance[12]\n";
	print "\tdisplay_ip(): $performance[13]\n";
	print "\tdisplay_tcp(): $performance[15]\n";
	print "\tgeo(): $performance[14]\n";
	print "\tbogonreq(): $performance[16]\n";
	print "\tbogon(): $performance[17]\n";
	my $subtimes = 0;
	foreach (@performance) {$subtimes += $_ if $_;}							
	my $finish = Time::HiRes::time();
	print "\tMain Program time: " . (($finish - $start) - $subtimes) . "\n";
	print "\tTotal Time: " . ($finish - $start) . "\n";
}

sub help {
	print "NAME\n";
	print "\ttcpunmask - Attempt to unmask sanitized data from TCP/IP packet\n\n";
	print "SYNOPSIS\n";
	print "\ttcpdump [ -vhdt ] packetdata\n\n";
	print "DESCRIPTION\n";
	print "\ttcpunmask takes a packet as input in ASCII-Hex format. Sanitized nibbles are formatted as ?'s. tcpunmask will attempt every possibly data value in place of these unknown nibbles and check to see if the checksum(s) match the ones reported in the packet data. Becuase of this, this script will not function if the checksums are also sanitized.\n\n";
	print "\tWhen finished, tcpmask will report all valid packets based on checksum matches. The report is displayed with values seperated by commas; this way you can redirect stdout to a csv file for further filtering\n\n";
	print "OPTIONS\n";
	print "\t-v\tVerbose. While brute forcing, this will display each packet that is currently being attempted, along with the calculated IP & TCP checksums\n\n";
	print "\t-h\tHelp. Displays this dialog\n";
	print "\t-d\tDebug. Because I haven't looked at 'perl -d' yet, So I go old school and use liberal 'print' statements here and there (only executed with -d)\n\n";
	print "\t-t\tThis is for performance debugging, it will give me the time spent for each subroutine, the main program, and total.\n\n";
	print "\t-b\tBogon Be-gone. With this enabled, current bogons will be filtered out of results (https://www.team-cymru.org/Services/Bogons/)\n\n";
	print "EXAMPLES\n";
	print "\tWe are guessing the last 2 octets of the Source IP Address, we would also like verbose mode\n";
	print "\t\ttcpunmask.pl -v 45000034001c4000400624a40a00????0a00010301bdc0bc984c4d618fb480cd8011038998DC00000101080a0bb24d88317a80f4\n";
	exit;
	#175CE005 is a bogon
}

my @guesses;		#Container for the offset locations of where ?'s are
my @guesses_tcp;	#Container for the offset locations of where ?'s are in TCP header
my $max_value;		#Container that stores the amount of brute force attempts needed (used for looping)
my $max_value_tcp;	#Container that stores the amount of brute force attempts needed for tcp (used for looping)
my $guess = 0;		#Container for the current guess we are on, it obviously starts at 0
my $guess_tcp = 0;	#Container for the current TCP guess we are on, it obviously starts at 0
my $try;			#The brute force data being tried (only stores the guess/unknwon data, not the entire packet)
my $try_tcp;		#The brute force data being tried for TCP
my $data_try;		#This is the actual data of the IP header along with the guess data integrated in
my $data_try_tcp;	#This is the actual data of the TCP header along with the guess data integrated in
my $i;				#A throwaway loop counter
my $progress;		#This is used to show user percent of progress of brute forcing

#Set up the data to be ready for brute forcing
$data = blackspace($data);			#Get rid of whitespace
my $ip_data = get_ipdata($data);	#Isolate out IP data
my $tcp_data = get_tcpdata($data);	#Isolate out TCP data

#Define "CSV" header in @results array, this array will also hold the results from brute forcing
if ($tcp_data) {
	@results = "IP Version,Header Length,Type of Service,Total Length,Identification,Flags/Frag,TTL(hops),Protocol,Checksum,Source Address,Destination Address,Source Port,Destination Port,Sequence Number,Acknowledgement Number,Offset,Reserved,Flags,Window,Checksum,Urgent Pointer,Data(w/options)\n";
} else {
	@results = "IP Version,Header Length,Type of Service,Total Length,Identification,Flags/Frag,TTL(hops),Protocol,Checksum,Source Address,Destination Address, Options\n";
}

my $original_sum = getsum($ip_data);		#Get the reported IP checksum in IP header
my $original_sum_tcp = getsumtcp($data) if ($tcp_data);	#Get the reported TCP checksum in TCP header, if there is TCP data to be had
print "Original IP sum: $original_sum\n" if $debug;			#(debug): Report what the IP Checksum is supposed to be
print "Original TCP sum: $original_sum_tcp\n" if $debug;	#(debug): Report what the TCP Checksum is supposed to be
@guesses = split(',',get_unknown($ip_data));	#get offset of unknown nibbles
my $nibbles_to_guess = @guesses;				#get amount of offsets (all we really needed...)
$max_value = 2 ** ($nibbles_to_guess * 4);		#numerical value to terminate bruteforcing on
@guesses_tcp = split(',',get_unknown_tcp($data));	#get offset of unknown nibbles
my $nibbles_to_guess_tcp = @guesses_tcp;			#get amount of offsets (all we really needed...)
$max_value_tcp = 2 ** ($nibbles_to_guess_tcp * 4);		#numerical value to terminate bruteforcing on

#This is the guts of the actual brute forcing
print "Attempting IP Brute forcing\n";			#Let user know that you are bruteforcing the IP headers
while ($guess < $max_value) {					#While we still have values to guess
	print "\x0d";								#Return to beginning of line
	$progress = ($guess / $max_value) * 100;	#Print percent complete
	printf '%.2f', $progress;					#with 2 decimal points
	print "% done";								#and percentage symbol at the end
	$try = asciihex($guess,$nibbles_to_guess);	#Create the data guess (just the guess, not whole packet)
	$data_try = createguess($ip_data, $try);	#Combine guess with packet

	#If Verbose is specified, print some stats out, like the packet and checksums of the current try
	my $status = "\tTrying IPHeader: " . $data_try . " " . checksum($data_try) . " for " . $original_sum if defined $options{v};
	$status =~ s/\n// if defined $options{v};	#"Chomp" it (if -v still)
	print $status if defined $options{v};		#print the status (-v)

	#Brute it
	if (checksum($data_try) =~ /$original_sum/i) {								#If the IP bruteforce attempt checksum result matches the expected one
		$guess_tcp = 0;
		while ($guess_tcp < $max_value_tcp) {						#While we still have values to guess
			$try_tcp = asciihex($guess_tcp,$nibbles_to_guess_tcp);	#Create the data guess (just the guess, not whole packet)
			$data_try_tcp = createguess($tcp_data, $try_tcp);		#Combine guess with packet
			if (($tcp_data) && (checksumtcp($data_try . $data_try_tcp)) =~ /$original_sum_tcp/i) {		#If theres TCP data, check that the same is true for TCP as well
				if ((defined $options{b}) && (bogon($data_try)) eq 'bogon') {
				} else {
					display_tcp($data_try . $data_try_tcp);			#If so, add it to our list of valid results
				}
											
			} elsif (!$tcp_data) {																	#If no tcp data
				if ((defined $options{b}) && (bogon($data_try)) eq 'bogon') {
				} else {
						display($data_try);																	#Still a match for IP, so print that
				}		
			}
		$guess_tcp++;
		}

	}
	$guess++;																					#Next Guess
}

geo();

print "\n@results\n";

perf() if (defined $options{t});

#I might need this some day...
#$hexstring = pack("C*", map { $_ ? hex($_) :() } $1);
