###################################---File Handle Code---##################################################
GetOptions('export=s' => \$export,			#Get csv filename
		'ratio=s' => \$ratio);			#change ratio if you want

#We are creating a report html file in the /tmp directory with a file format of "report-timestamp.html"
open REPORT, ">/tmp/report-$start.html" or die "You don't have permissions to write that file $!\n";

open SPREADSHEET, "$export" or die "$export: $!";	#Our file handle for the .csv is SPREADSHEET
$/ = undef;						#Turn of newlines
$entire = <SPREADSHEET>;				#Get entire spreadsheet as a string
$/ = "\n";						#Turn newlines back on
close SPREADSHEET or die "$export: $!";		#Close the file handle

#Start setting up REPORT html output
print REPORT "<html>\n<head>\n<title>Report $start</title>\n</head>\n<body>\n";
###########################################################################################################


##############################---Build our Spreadsheet Data Structure---###################################
$entire_persisted = length($entire);	#Get length of our data real quick
#Get amount of columns
my $first_row;				#Array to store only first row of csv (headers)
if ($entire =~ /(.+)\n/) {		#extract everything until newline (headers shouldn't have them)
	$first_row = $1;		#store entire first line
}
@fields = split(/,/, $first_row);	#split header fields up by comma into @fields array
#print "the 30th field is $fields[34]\n\n";
$column_amount = @fields;		#Indentify how many columns our csv has
$column_amount--;			#It's actually 1 less...

#Attempt to parse all fields with re-inveted wheel
$| = 1;			#Autoflush stdout
$incrementer = 0;	#init incrementer
while (length($entire) > 2) {	#while we still have data in our spreadsheet
	#Starts with "[our field]", OR
	#Starts with no commas or quotes but anything else (which is our field), then comma OR
	#Starts with quote, then literally "<R", then anything followd by comma (not a field)
	if (($entire =~ /^"(.*?)",/s) || ($entire =~ /^([^,"]*?),/s) || ($entire =~ /^"<R.+?,/s)) {
		$field = $1;	#The actual field
		$match = $&;	#The entire match
		@all = (@all, $field);	#add this field to our all fields array
		$entire =~ s/\Q$match\E//;	#remove the match from our entire spreadsheet data
		#incrementor / the amount of columns will be zero when we pass an entire row
		if ($incrementer % $column_amount eq 0) {
			print "\x0d";				#Start at beginning of line
			print "\t\t\t\tCurrently parsing row: ";	
			print ($incrementer / $column_amount);	#print the row we are on (this is an estimate)
		}
		$incrementer++;	#next field
 		$percent = sprintf("%.2f", 100 - ((length($entire) / $entire_persisted) *100));
		print "\x0d$percent% Done | Data remaining:" . length($entire) . " ";
	#For debugging
	} elsif (length($entire) < 30){
		@all = (@all, $field);	#add this field to our all fields array
		$entire = "";
	} else {
		print "failed to match\n\n$entire\n";
		exit;
	}
	
}

#get header names into @headers array
$incrementer = 0;	#init incrementer
$column_amount++;	#There's an extra column, this isn't elegant, but better than exotic parsing above
while ($incrementer < $column_amount) {		#go through all columns
	$headers[$incrementer] = shift(@all);	#shift next header name into @headers array indexed by incrementer
	$incrementer++;				#next
}
$headers[--$incrementer] =~ s/\n.*//g;		#Go back to last column and remove bleed of next field :(
$column_amount--;	#Return to actual colums


#assoc header names with corresponding index value (column number) in a hash
$incrementer = 0;
$column_amount++;	#There's an extra column, this isn't elegant, but better than exotic parsing above
while ($incrementer < $column_amount) {				#go through all columns
	$columns{ $headers[$incrementer] } = $incrementer;      #hash, using variables
	$incrementer++;						#next
}
$column_amount--;	#Return to actual colums

#populate 2-level array, note that there are no longer headers in @all due to shifting to populate @headers
while (@all) {
	$incrementer = 0;				#init incrementer
	while ($incrementer < $column_amount) {		#go through all columns
		#shift the next field into $spreadsheet[row number we are on][column index]
		$spreadsheet[$row_incrementer][$incrementer] = shift(@all);
		$incrementer++;				#next column
	}

	$spreadsheet[$row_incrementer][--$incrementer] =~ s/\s\w{3}\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d//g;
	$row_incrementer++;				#next row
}

#Determine how many rows we actually had, for debugging
$row_ammount = @spreadsheet;
print "\nRow was actually: $row_ammount\n";
