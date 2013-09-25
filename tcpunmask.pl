#!/usr/bin/perl
#TCP Unmask is a tool that attempts to recover sanitized data from an IP header (hopefully TCP as well). It is able to do this when people forget to also sanitize their checksums.
#This tool is still barely "alfa", it is on git right now so I can access it everywheres I code at. It only does IP headers, and the IP header has to be hardcoded to $data var (hardly "production" quality code)
use warnings;
use strict;
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
	$sum =~ s/(\w{20})....(.+)/$1$2/;	#Get rid of checksum bytes

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
	while ($i lt $wordcount) {
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

	$sum =~ tr/0123456789ABCDEF/FEDCBA9876543210/;

	return $sum
}

#Gets the checksum reported by IP header (not calculated)
sub getsum($) {
	my $sum = shift;
	$sum =~ s/^.{20}(....).+$/$1/;	#Get rid of checksum bytes
	return $sum;
}

#Get comma seperated list of offsets where ?'s are found
sub get_unknown($) {
	my $header = shift;
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
	print hex($ipver) . ",";
	print $headl * 4 . ",";
	print "$tos,";			#would like to improve this
	print hex($tl) . ",";
	print "$id,";
	print "$frag,";			#would like to improve this
	print hex($ttl) . ",";
	print "$prot,";			#would like to make this more granular
	print "$sum,";
	display_ip($saddr);
	print ",";
	display_ip($daddr);
	print ",$options" if $options;
	print "\n";
}

sub display_ip {
	my $ip = shift;
	if ($ip =~ /(..)(..)(..)(..)/) {
		print hex($1) . "." . hex($2) . "." . hex($3) . "." . hex($4); 
	}
}

sub geo {
	open IN, 'GeoLiteCity-Blocks.csv' or die "The file has to actually exist, try again $!\n";	#input filehandle is IN

	close IN;
}

#my $data = "4500 003c 1c46 4000 4006 b1e6 ac10 0a63 ac10 0a0c";
my $data = "45 00 05 dc d3 65 40 00 78 06 df b1 0a b0 39 e5 0a 6b fb 04";
my @guesses;
my $max_value;
my $guess = 0;
my $try;
my $data_try;
my $i;

print "IP Version,Header Length,Type of Service,Total Length,Identification,Flags/Frag,TTL(hops),Protocol,Checksum,Source Address, Destination Address, Options?\n";

$data = blackspace($data);			#Get rid of whitespace
my $original_sum = getsum($data);
@guesses = split(',',get_unknown($data));	#get offset of unknown nibbles
my $nibbles_to_guess = @guesses;		#get amount of offsets
$max_value = 2 ** ($nibbles_to_guess * 4);		#numerical value to terminate bruteforcing on

while ($guess < $max_value) {
	$try = asciihex($guess,$nibbles_to_guess);	
	$data_try = createguess($data, $try);
	if (checksum($data_try) =~ /$original_sum/i) {
		display($data_try);
	}
	$guess++;
}

geo();


#$hexstring = pack("C*", map { $_ ? hex($_) :() } $1);
