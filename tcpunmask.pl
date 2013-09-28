#!/usr/bin/perl
#TCP Unmask is a tool that attempts to recover sanitized data from an IP header (hopefully TCP as well). It is able to do this when people forget to also sanitize their checksums.
use warnings;
use strict;
use Getopt::Std;
##Whishlist
	#TCP!
	#Make outputs more granular / more better
	#add progress indicator
	#Add GeoIP datas
	#Cross reference bogons
	#Add --options to reduce invalid fields
		#only ipv4
		#ip header length below 20 is invalid
		#etc...

my %options=();
my $debug = 0;
getopts("dv", \%options);
$debug = 1 if defined $options{d};
my @results = "IP Version,Header Length,Type of Service,Total Length,Identification,Flags/Frag,TTL(hops),Protocol,Checksum,Source Address, Destination Address, Options/TCP data\n";
my $result_line;

###############SubRoutines################

#Get rid of newlines and whitespace
sub blackspace($) {
   	my $header = shift;
	$header =~ s/\s|\n//g;
	return $header;
}

#Calculate checksum given IP header info
sub checksum($){
	my $sum = shift;
	my $length;
	if ($sum =~ /^.(.)/) { 
		$length = hex($1);
		print "header length hex: $length\n" if $debug;
		$length *= 4;
		$length = ($length * 2) - 24;
		print "header length offset: $length\n" if $debug;
	}
	$sum =~ s/^(\w{20})....(.{$length}).*/$1$2/;	#Get rid of checksum bytes
	print "data without checksum: $sum\n" if $debug;

	my $i = 0;
	my @words;
	#Get 2byte words for all header data (to sum)
	while ($sum) {
		if ($sum =~ /^(.{4})/) {
			$words[$i] = $1;
		$sum =~ s/^.{4}//;
		}
		$i++;
	}

	my $wordcount = @words;
	$i = 0;
	$sum = 0;
	while ($i < $wordcount) {
		$sum += hex($words[$i]);
		$i++;
	}

	my $hexsum = sprintf("%.4X\n", $sum);
	my $carry;
	if ($hexsum =~ /(.).{4}/) {
		$carry = $1;
	} else {
		$carry = 0;
	}

	$sum += $carry;
	$sum = sprintf("%.4X\n", $sum);
	if ($sum =~ /.(.{4})/) {
		$sum = $1;
	}

	$sum =~ tr/0123456789ABCDEF/FEDCBA9876543210/;	#mathemetically equiv to FFFF-$sum or 1's compliment

	print "ip_checksum: $sum\n" if $debug;
	return $sum;
}

#Gets the checksum reported by IP header (not calculated)
sub getsum($) {
	my $sum = shift;
	$sum =~ s/^.{20}(....).+$/$1/;	#Get rid of checksum bytes
	return $sum;
}

sub checksumtcp($){
	my $sum = shift;
	my $offset = offset($sum);
	my $saddr;
	my $daddr;
	my $saddr1;
	my $saddr2;
	my $daddr1;
	my $daddr2;
	my $tlength;
	my $tcplength;
	my $offsetz = $offset - 16;	#amount of values just before IP addresses
	if ($sum =~ /^.{$offsetz}(.{8})(.{8}).*/) {
		$saddr = $1;
		$daddr = $2;
	}
	if ($sum =~ /^.{4}(.{4}).+/) {
		$tlength = hex($1);
	}
	$tcplength = $tlength - ($offset/2);
	$tcplength = sprintf("%.4X\n", $tcplength);
	chomp($tcplength);

	my $tcp_data = $sum;
	$tcp_data =~ s/^.{$offset}(.*)/$1/;

	my $tcp_without_sum = $tcp_data;
	$tcp_without_sum =~ s/^(.{32}).{4}(.+)/$1$2/;

	my $i = 0;
	my @words;
	#Get 2byte words for all header data (to sum)
	while ($tcp_without_sum) {
		if ($tcp_without_sum =~ /^(.{4})/) {
			$words[$i] = $1;
		$tcp_without_sum =~ s/^.{4}//;
		}
		$i++;
	}

	if ($saddr =~ /(.{4})(.{4})/) {
		$saddr1 = $1;
		$saddr2 = $2;
	}
	if ($daddr =~ /(.{4})(.{4})/) {
		$daddr1 = $1;
		$daddr2 = $2;
	}

	@words = (@words, '0006', $saddr1, $saddr2, $daddr1, $daddr2, $tcplength);

	my $wordcount = @words;
	$i = 0;
	$sum = 0;
	while ($i < $wordcount) {
		$sum += hex($words[$i]);
		$i++;
	}

	my $hexsum = sprintf("%.4X\n", $sum);
	my $carry;
	if ($hexsum =~ /(.).{4}/) {
		$carry = $1;
	} else {
		$carry = 0;
	}

	$sum += $carry;
	$sum = sprintf("%.4X\n", $sum);
	if ($sum =~ /.(.{4})/) {
		$sum = $1;
	}

	$sum =~ tr/0123456789ABCDEF/FEDCBA9876543210/;	#mathemetically equiv to FFFF-$sum or 1's compliment

	print "tcp_checksum: $sum\n" if $debug;
	return $sum;
}

sub getsumtcp($) {
	#I will eventually have to do a sanity check with the IP header length (when that nibble is an unknown)
	my $sum = shift;
	my $offset = offset($sum);
	$sum =~ s/^.{$offset}.{32}(....).*/$1/;	
	return $sum;
}

#Get comma seperated list of offsets where ?'s are found
sub get_unknown($) {
	my $header = shift;
	my $offset = offset($header);
	$header =~ s/^(.{$offset}).*/$1/;
	my @nibbles = split('',$header);
	my $nibblecount = @nibbles;
	my $i = 0;
	my $questions = "";
	while ($i < $nibblecount) {
		$questions .= ',' . $i if ($nibbles[$i] eq '?');
		$i++;
	}
	$questions =~ s/^,//;
	return $questions;
}

sub get_unknown_tcp($) {
	my $header = shift;
	my $offset = offset($header);
	$header =~ s/^.{$offset}(.*)/$1/;
	#print "TCP header: $header\n";
	my @nibbles = split('',$header);
	my $nibblecount = @nibbles;
	my $i = 0;
	my $questions = "";
	while ($i < $nibblecount) {
		$questions .= ',' . $i if ($nibbles[$i] eq '?');
		$i++;
	}
	$questions =~ s/^,//;
	return $questions;
}

sub get_ipdata{
	my $ip_data = shift;
	my $offset = offset($ip_data);
	if ($ip_data =~ /^(.{$offset}).*/) {
		$ip_data = $1;
	}
	return $ip_data;
}

sub get_tcpdata{
	my $tcp_data = shift;
	my $offset = offset($tcp_data);
	if ($tcp_data =~ /^.{$offset}(.*)$/) {
		$tcp_data = $1;
	}
	return $tcp_data;
}

sub offset {
	my $sum = shift;
	my $offset;
	if ($sum =~ /^.(.)/) {
		$offset = $1;
		$offset *= 8;	#offset nibble times 4 (bytes) (but * 8 becuase each nibble is a character)
	}
	return $offset;
}

sub asciihex {
	my $hexstring = $_[0];
	my $nibbles = $_[1];
	$hexstring = sprintf("%.${nibbles}X\n", $hexstring);
	return $hexstring;
}

sub createguess {
	#Get params
	my $data = $_[0];
	my $try = $_[1];

	my @trys = split('',$try);	#make each guess nibble seperate
	my $nibbles = @trys;

	my $i = 0;
	while ($i < $nibbles) {
		$data =~ s/\?/$trys[$i]/;
		$i++;
	}

	#print "\n$data\n";
	#print "$try\n";

	return $data;
}

sub display {
	my $data = shift;
	$result_line = "";
	my ($ipver,$headl,$tos,$tl,$id,$frag,$ttl,$prot,$sum,$saddr, $daddr, $options);
	if ($data =~ /(.)(.)(..)(....)(....)(....)(..)(..)(....)(.{8})(.{8})(.*)/) {
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
		$options = $12 if ($12);
	}
	$result_line .= hex($ipver) . "," . $headl * 4 . "," . "$tos," . hex($tl) . "," . "$id," . "$frag," . hex($ttl) . "," . "$prot," . "$sum,";
	display_ip($saddr);
	$result_line .= ",";
	display_ip($daddr);
	$result_line .= ",$options" if $options;
	$result_line .= "\n";
	@results = (@results, $result_line);
}

sub display_ip {
	my $ip = shift;
	if ($ip =~ /(..)(..)(..)(..)/) {
		$result_line .= hex($1) . "." . hex($2) . "." . hex($3) . "." . hex($4);
	}
}

sub geo {
	open IN, 'GeoLiteCity-Blocks.csv' or die "The file has to actually exist, try again $!\n";	#input filehandle is IN

	close IN;
}

#my $data = "4500 003c 1c46 4000 4006 b1e6 ac10 0a63 ac10 0a0c";
#my $data = "45 00 05 dc d3 65 40 00 78 06 13 b2 0a 00 01 02 0a 00 01 03";
my $data = "45 00 00 34 00 1c 40 00 40 06 24 a4 0a 00 01 02 0a 00 01 03 01 bd c0 bc 98 4c 4d 61 8f b4 80 cd 80 11 03 89 98 DC 00 00 01 01 08 0a 0b b2 4d 88 31 7a 80 f4"; #full TCP packet
#tcp bd
#my $data = "46 00 05 dc d3 65 40 00 78 06 b4 23 0a b0 39 e5 ?? 6b fb 04 01 02 03 04";
my @guesses;
my $max_value;
my $guess = 0;
my $try;
my $data_try;
my $i;
my $progress;

$data = blackspace($data);			#Get rid of whitespace

my $ip_data = get_ipdata($data);
my $tcp_data = get_tcpdata($data);

my $original_sum = getsum($ip_data);
@guesses = split(',',get_unknown($ip_data));	#get offset of unknown nibbles
my $nibbles_to_guess = @guesses;		#get amount of offsets
$max_value = 2 ** ($nibbles_to_guess * 4);		#numerical value to terminate bruteforcing on

print "Attempting IP Brute forcing\n";
while ($guess < $max_value) {
	print "\x0d";
	$progress = ($guess / $max_value) * 100;
	printf '%.2f', $progress;
	#print $progress;
	print "% done";
	$try = asciihex($guess,$nibbles_to_guess);
	$data_try = createguess($ip_data, $try);	
	print "\tTrying Packet: $data_try" if defined $options{v};
	if (checksum($data_try) =~ /$original_sum/i) {
		display($data_try);
	}
	$guess++;
}

my $original_sum_tcp = getsumtcp($data);
print "Original TCP sum: $original_sum_tcp\n" if defined $debug;
my @tcp_guesses = split(',',get_unknown_tcp($data));
print "tcp_guesses: @tcp_guesses\n";
my $tcp_nibbles_to_guess = @tcp_guesses;		#get amount of offsets
print "nibbles to guess: $tcp_nibbles_to_guess\n";
my $tcp_max_value = 2 ** ($tcp_nibbles_to_guess * 4);		#numerical value to terminate bruteforcing on
print "tcp max value is: $tcp_max_value\n";


print "Attempting TCP Brute forcing\n";
$guess = 0;
while ($guess < $tcp_max_value) {
	print "\x0d";
	$progress = ($guess / $tcp_max_value) * 100;
	printf '%.2f', $progress;
	#print $progress;
	print "% done";
	$try = asciihex($guess,$tcp_nibbles_to_guess);
	$data_try = createguess($tcp_data, $try);	
	print "\tTrying Packet: $data_try" if defined $options{v};

	#This form wont work, this will need to be nested in IP bruting, as we need IP address guesses as well :(
#	if (checksumtcp($data_try) =~ /$original_sum_tcp/i) {
#		displaytcp($data_try);										#need a display tcp
#	}
	$guess++;
}


checksumtcp($data);

geo();

print "\n@results\n";


#$hexstring = pack("C*", map { $_ ? hex($_) :() } $1);
