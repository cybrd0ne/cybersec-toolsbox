#!/usr/bin/perl -w

# Perl script to parse Firefox places.sqlite and downloads.sqlite
# Based on Kristinn Gudjonsson's "ff3histview" Perl script (http://blog.kiddaland.net/dw/ff3histview) and
# Mark-Jason Dominus's "A Short Guide to DBI" article (http://www.perl.com/pub/1999/10/DBI.html)
# Works with SIFT's Firefox V3.6.17 and WinXP's Firefox V11.0
# Be sure to run "sudo cpan DBI" to update the DBI Perl package before running!

use strict;

use Getopt::Long;
use DBI;

my $version = "ffparser.pl v2012-03-19";
my $help = 0;
my $bk = 0;
my $dload = 0;
my $hist = 0;
my $path = "";

GetOptions('help|h' => \$help,
    'bk' => \$bk,
    'dload' => \$dload,
    'hist' => \$hist,
    'path=s' => \$path);

if ($help || $path eq "" || (!$bk and !$dload and !$hist))
{
    print("\nHelp for $version\n\n");
    print("Perl script to parse Firefox places.sqlite and downloads.sqlite\n"); 
    print("\nUsage: ffparser.pl [-h|help] [-path pathname] [-bk] [-dload] [-hist]\n");
    print("-h|help .......... Help (print this information). Does not run anything else.\n");
    print("-path pathname ... Path to folder containing places.sqlite and downloads.sqlite.\n");
    print("-bk .............. Parse for Bookmarks (Date Added, Title, URL, Count).\n");
    print("-dload ........... Parse for Downloaded items (Download Ended, Source, Target, Current No. Bytes).\n");
    print("-hist ............ Parse for History (Date Visited, Title, URL, Count).\n");
    print("\nExample: ffparser.pl -path /cases/firefox/ -bk -dload -hist");
    print("\nNote: Trailing / at end of path\n");
    exit;
}

# For now, ass-ume downloads.sqlite, places.sqlite are in the path provided
# Also, ass-ume that the path has a trailing "/" eg TAB autocompletion used
print "Running $version\n";

# Try read-only opening "places.sqlite" to extract the Big Endian 4 byte SQLite Version number at bytes 96-100
# The version number will be in the form (X*1000000 + Y*1000 + Z) 
# where X is the major version number (3 for SQLite3), Y is the minor version number and Z is the release number 
# eg 3007004 for 3.7.4
my $placesver=0;
open(my $placesfile, "<".$path."places.sqlite") || die("Unable to open places.sqlite for version retrieval\n");
#binmode($placesfile);
seek ($placesfile, 96, 0);
sysread ($placesfile, $placesver, 4)|| die("Unable to read places.sqlite for version retrieval\n");; 
# Treat the 4 bytes as a Big Endian Integer
my $placesversion = unpack("N", $placesver);
print("\nplaces.sqlite SQLite Version is: $placesversion\n");
close($placesfile);

# Extract/Print the SQLite version number for downloads.sqlite as well
my $dloadsever=0;
open(my $dloadsfile, "<".$path."downloads.sqlite") || die("Unable to open downloads.sqlite for version retrieval\n");
#binmode($dloadsfile);
seek ($dloadsfile, 96, 0);
sysread ($dloadsfile, $dloadsever, 4)|| die("Unable to read downloads.sqlite for version retrieval\n");; 
# Treat the 4 bytes as a Big Endian Integer
my $dloadsversion = unpack("N", $dloadsever);
print("downloads.sqlite SQLite Version is: $dloadsversion\n");
close($dloadsfile);

# Open the places.sqlite database file first
if ($bk or $hist)
{
    my $db = DBI->connect("dbi:SQLite:dbname=$path"."places.sqlite","","") || die( "Unable to connect to database\n" );
    
    # Checks if this is a valid Firefox places.sqlite
    $db->prepare("SELECT id FROM moz_places LIMIT 1") || die("The database is not a correct Firefox database".$db->errstr);

    if ($bk)
    {
        print "\nNow Retrieving Bookmarks ...\n";

        my $sth =  $db->prepare("SELECT datetime(moz_bookmarks.dateAdded/1000000, 'unixepoch') AS \'Date Added\', moz_bookmarks.title AS Title, moz_places.url AS URL, moz_places.visit_count AS Count FROM moz_bookmarks, moz_places WHERE moz_places.id = moz_bookmarks.fk ORDER BY moz_bookmarks.dateAdded ASC");
    
        $sth->execute();

        print $sth->{NUM_OF_FIELDS}." fields will be returned\n";
        PrintHeadings($sth);
        PrintResults($sth);

        # We print out the no. rows now because apparently $sth->rows isn't set until AFTER
        #  $sth->fetchrow_array() has completed in PrintResults
        if ($sth->rows == 0) 
        {
            print "No Bookmarks found!\n\n";
        }
        else
        {    
            print $sth->rows." Rows returned\n"; 
        }
        $sth->finish;
    }

    if ($hist)
    {
        print "\nNow Retrieving History ...\n";

        my $sth =  $db->prepare("SELECT datetime(moz_historyvisits.visit_date/1000000, 'unixepoch') AS \'Date Visited\', moz_places.title AS Title, moz_places.url AS URL, moz_places.visit_count AS Count FROM moz_historyvisits, moz_places WHERE moz_historyvisits.place_id = moz_places.id ORDER BY moz_historyvisits.visit_date ASC");
    
        $sth->execute();

        print $sth->{NUM_OF_FIELDS}." fields will be returned\n";
        PrintHeadings($sth);
        PrintResults($sth);

        if ($sth->rows == 0) 
        {
            print "No History found!\n\n";
        }
        else
        {    
            print $sth->rows." Rows returned\n"; 
        }

        $sth->finish;
    }

    $db->disconnect;
}

if ($dload)
{
    # Now we open the downloads.sqlite database file
    print "\nNow Retrieving Downloads ...\n";

    my $db = DBI->connect("dbi:SQLite:dbname=$path"."downloads.sqlite","","") || die( "Unable to connect to database\n" );

    # No further checks, we go straight into our query because it IS possible to have an empty moz_downloads table.
    my $sth =  $db->prepare("SELECT datetime(endTime/1000000, 'unixepoch') AS \'Download Ended\', source AS Source, target AS Target,  currBytes as \'Current No. Bytes\' FROM moz_downloads ORDER BY moz_downloads.endTime ASC");
    
    $sth->execute();

    print $sth->{NUM_OF_FIELDS}." fields will be returned\n";
    PrintHeadings($sth);
    PrintResults($sth);

    if ($sth->rows == 0) 
    {
        print "No Downloads found!\n\n";
    }
    else
    {    
        print $sth->rows." Rows returned\n"; 
    }

    $sth->finish;

    $db->disconnect;
}

# end main

sub PrintHeadings
{
    my $sth = shift;

    # Print field headings
    for (my $i = 0; $i <= $sth->{NUM_OF_FIELDS}-1; $i++)
    {
        if ($i == $sth->{NUM_OF_FIELDS} - 1)
        {
            print $sth->{NAME}->[$i]."\n"; #last item adds a newline char
        }
        else
        {    
            print $sth->{NAME}->[$i]." | ";
        }
    }
}

sub PrintResults
{
    my $sth = shift;
    my @rowarray;

    # Prints row by row / field by field
    while (@rowarray = $sth->fetchrow_array() )
    {
        for (my $i = 0; $i <= $sth->{NUM_OF_FIELDS}-1; $i++)
        {
            if ($i == $sth->{NUM_OF_FIELDS} - 1 )
            {
                print $rowarray[$i]."\n"; #last field in row adds newline
            }
            else
            {
                if ($rowarray[$i])
                {
                    print $rowarray[$i]." | ";
                }
                else
                {
                    print " | "; # field returned could be UNDEFINED, just print separator
                }
            }
        }
    }
}
