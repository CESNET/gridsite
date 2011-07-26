#!/usr/bin/perl
use Switch;
use File::Copy;
use Getopt::Std;

	# ******************************
	# CMDline args
	# ******************************

	getopts('hv');

$usage = qq{
$0 downloads the contents of the GridSite Wiki and uses that to produce EMI-style PDF documentation.

usage: $0 [-h] [-v]
	
-h  Print this help and exit
-v  Verbose output

};
	if (defined $opt_h) {die $usage};

	if (defined $opt_v) {
		$qopt_devnull="";
		$qopt_q="";
	}
	else {
		$qopt_devnull=" > /dev/null 2> /dev/null";
		$qopt_q="-q";
	}


	# ******************************
	# Init All
	# ******************************

	printf("Checking for required binaries...");
	check_req("rm", "mv", "mkdir", "grep", "egrep", "wget", "cat", "awk", "sed", "gnuhtml2latex", "pdflatex", "base64", "convert");

	printf("\nSetting up...");
	$TMPDIR=$ENV{'TMPDIR'};
	if ($TMPDIR eq "") {$TMPDIR="/tmp";}

#	$WRKDIR="/tmp/gsdoc_2989"; # XXX: back to autodetect
	$WRKDIR="$TMPDIR/gsdoc_$$";
	system("mkdir -p $WRKDIR");
	chdir($WRKDIR);

#	system("rm -f striphead_* striptail_* *.html *.tex *.cls *.pdf GridSite_all.* GridSite_UG.* GridSite_AG.* GridSite_DESC.* .* *.gif *.png");

	# ******************************
	# Hard-code contents
	# ******************************

	# This is a set of arrays that define contents of various documents.
	# Give names of individual wiki pages to include them into the doc
	# 'all' will first include all the listed pages and then all unlisted
	# ones

	%docs = (
		UG => [ qw/User_Guide/ ],
		AG => [ qw/Build_and_Install_Guide Config_Guide Administration_Guide/ ],
		DESC => [ qw/Module_Architecture Delegation_protocol/ ],
		all => [ qw/ GridSite Module_Architecture / ]
	);

	%titles = (
		UG => 'GridSite -- User Guide', 
		AG => 'GridSite -- Administrator Guide', 
		DESC => 'GridSite -- Functional Description', 
		all => 'GridSite' 
	);

	# ******************************
	# Get Content
	# ******************************

	printf("\nDownloading content...");
	system("wget --no-check-certificate $qopt_q -r -l 1 -nd -k -p -I wiki --no-parent https://www.gridsite.org/wiki/Special:Allpages");
	system("rm -f $WRKDIR/*:*");
	

	opendir(WRKD, $WRKDIR) || die("Cannot open directory $WRKDIR");
	@allfiles = readdir(WRKD);
	closedir(WRKD);

	# ******************************
	# Prepare LaTeX structures
	# ******************************

	gen_emi_cls();
	gen_emi_logo();
	gen_wget();

	# ******************************
	# Produce LaTeX chapters
	# ******************************

	printf("\nProcessing files...");

	foreach $f (@allfiles) {
		unless ( ($f eq ".") || ($f eq "..") ) {
			#Get and prepend Title
			$title=`egrep -a "class=.firstHeading.>" $f `;
			$title=~s/<\/{0,1}h1.*?>//g;
			chomp($title);
			system("echo '<HTML><BODY><H1>$title</H1>' > $f.html");
			
			# Strip front and tail matter
			system("awk '!p;/-- end content --/{p=1}' $f | awk '/-- start content --/{p=1}p' >> $f.html");

			# Remove Table of Contents, if present
			$toc_present=`grep -E 'table.*toctitle' $f.html`;
			unless ($toc_present eq "") {
				system("awk '!p;/<table.*toctitle/{p=1}' $f.html | egrep -v '<table.*toctitle' > $f.front.html");
				system("awk '/<.table>/{p=1}p' $f.html | tail -n +2 > $f.rear.html");

				system("cat $f.front.html > $f.html");
				system("cat $f.rear.html >> $f.html");

				system("rm $f.front.html $f.rear.html");
			}

			# Add false beginings and ends
			system("echo '</BODY>' >> $f.html");
			system("echo '</HTML>' >> $f.html");

			# Convert format, making sure that fake wget gets called first :-/
			# This is a workaround for an apparent bug in gnuhtml2latex v 0.4-1,
			# which sticks option -nc between -O and the actual file name.
			system("PATH=.:\$PATH gnuhtml2latex -a EMI -n -g $f.html $qopt_devnull");

			# Strip LaTeX matter
			system("mv $f.tex $f.latex");
			system("awk '!p;/end{document}/{p=1}' $f.latex | awk '/begin{document}/{p=1}p' | egrep -v 'end{document}' | egrep -v 'begin{document}' >> $f.tex");
			system("rm $f.latex");

			# Custom fixes
			system("sed -i 's/^\\\\par \\\\\\\\//' $f.tex"); #Remove empty paragraphs
			system("sed -i 's/^\\[edit\\]//' $f.tex"); #Remove remaining [edit] clauses
			system("sed -i 's/^Retrieved from.*//' $f.tex"); #Remove "retrieved from" remarks
			system("sed -i 's/^Categories:.*//' $f.tex"); #Remove wiki categories
			system("sed -i 's/\\\\par Categories:.*//' $f.tex"); #Remove wiki categories, take 2

#			printf("\n$f ready");

		}
	}
	
	# *************************************
	# Convert unsupported graphics formats
	# *************************************

	printf("\nConverting unsupported graphic formats...");

	@presentfiles = <*>;

	@extensions = ( "gif", "jpg", "jpeg", "tif", "tiff" );

	$i = 0;

	foreach $img (@presentfiles) {
		foreach $ext (@extensions) {
			if ($img=~m/\.$ext$/i) {
				move($img,"inclfile$i.$ext");
				system("convert inclfile$i.$ext inclfile$i.png");
				system("sed -i 's/$img/inclfile$i.png/' *.tex");
				$i++;
			}
		}
	}

	# ******************************
	# Generate overall LaTeX files
	# ******************************

	printf ("\nGenerating LaTeX doc files...");

	for $doc ( keys %docs ) {

		$texfilename = sprintf "GridSite_$doc.tex";

		if (defined $opt_v) { printf "\n* $doc ($titles{$doc}): $texfilename"; }

		gen_LaTeX_files($texfilename);

		system("sed -i 's/XXTITLEXX/$titles{$doc}/' $texfilename");
		system("sed -i 's/XXAUTHORXX/CESNET/' $texfilename");
		system("sed -i 's/XXVERSIONXX/1.0.0-1/' $texfilename");
		system("sed -i 's/XXEMIVERSIONXX/1.x/' $texfilename");

		foreach $chapter (@{ $docs{$doc} }) {
			if (defined $opt_v) { printf "\n - $chapter"; }
			# Add to final document
			system("echo \"\\input{$chapter.tex}\" >> $texfilename");
		}
	}


	# Special treatment of 'all'
	printf("\nAdding all unlisted to 'GridSite_all'...");
	foreach $f (@allfiles) {
		unless ( ($f eq ".") || ($f eq "..") ) {
			unless(grep $_ eq $f, @{ $docs{all} }) {
				system("echo \"\\input{$f.tex}\" >> GridSite_all.tex");
				if (defined $opt_v) { printf("\n  - $f"); }
			}
		}
	}

	for $doc ( keys %docs ) {

		$texfilename = sprintf "GridSite_$doc.tex";
		system("echo '\\end{document}' >> $texfilename");
	}

	# ******************************
	# Build
	# ******************************

	printf("\nBuilding PDFs...");
	for $doc ( keys %docs ) {
		$texfilename = sprintf "GridSite_$doc.tex";
		system("pdflatex $texfilename $qopt_devnull");
		system("pdflatex $texfilename $qopt_devnull"); #Twice for TOC, page and ref. numbers to regenerate correctly.
	}

	# ******************************
	# Final Bows
	# ******************************


	printf("\n\nOutput is in $WRKDIR\n");
	for $doc ( keys %docs ) {
		$pdffilename = sprintf "GridSite_$doc.pdf";
		printf("$WRKDIR/$pdffilename\n");
	}
	printf ("\n");

	# ******************************
	# Subroutines
	# ******************************


sub check_req {

	my $fail=0;

	for($i=0;$i<=$#_;$i++){
		system("which $_[$i] > /dev/null");
		if ($? >> 8) { printf "\n$_[$i]... Not found"; $fail = 1; }
		else {
			if (defined $opt_v) { printf "\n$_[$i]... OK"; }
		}
	}

	if ($fail) {printf "\n\nSome required binaries were not found!\n"; die; }
}


sub gen_wget {

	open T,">wget.b64" or die "wget.b64: $!\n";

	print T q{IyEvdXNyL2Jpbi9wZXJsCgokYXJncyA9IGpvaW4gIiAiLCBAQVJHVjsKCiRhcmdzPX5zLy1uYyAv
LzsKc3lzdGVtKCJYWFdHRVRYWCAtLW5vLWNoZWNrLWNlcnRpZmljYXRlICRhcmdzIik7Cg==};

	close T;
	system("base64 -d -i wget.b64 > wget");
	system("rm wget.b64");

	$wgetpath=`which wget`;
	chomp($wgetpath);
	system("sed -i 's!XXWGETXX!$wgetpath!' ./wget");
	system ("chmod +x ./wget");

}

sub gen_LaTeX_files {

#	printf "gen_LaTeX_files: $_[0]";

	open T,">$_[0].b64" or die "$_[0].b64: $!\n";

	print T q{XGRvY3VtZW50Y2xhc3NbXXtlbWl9Clx1c2VwYWNrYWdlW3V0Zjhde2lucHV0ZW5jfQpcdXNlcGFj
a2FnZVtwZGZ0ZXhde2dyYXBoaWN4fQpcdXNlcGFja2FnZVtde2NvbW1lbnR9CgpcdGl0bGV7WFhU
SVRMRVhYfQpcYXV0aG9ye1hYQVVUSE9SWFh9ClxEYXRle1x0b2RheX0KXERvY1ZlcnNpb257WFhW
RVJTSU9OWFh9ClxFTUlDb21wVmVyc2lvbntYWEVNSVZFUlNJT05YWH0KClxiZWdpbntkb2N1bWVu
dH0KClx0YWJsZW9mY29udGVudHMKClxuZXdwYWdlCgo=};

	close T;
	system("base64 -d -i $_[0].b64 > $_[0]");
	system("rm $_[0].b64");

}

sub gen_emi_cls {
	open T,">emi.cls.b64" or die "emi.cls.b64: $!\n";

	print T q{CgpcTmVlZHNUZVhGb3JtYXR7TGFUZVgyZX0KXFByb3ZpZGVzQ2xhc3N7ZW1pfVsyMDExLzAzLzI0
IEVNSSBMYVRlWCBDbGFzc10KXHR5cGVvdXR7RU1JIExhVGVYIGNsYXNzIC0tIDIwMTEvMDMvMjR9
CgoKXERlY2xhcmVPcHRpb24qe1xQYXNzT3B0aW9uc1RvQ2xhc3N7XEN1cnJlbnRPcHRpb259e2Fy
dGljbGV9fQpcUHJvY2Vzc09wdGlvbnMKCgpcTG9hZENsYXNzWzExcHRde2FydGljbGV9CgpcUmVx
dWlyZVBhY2thZ2V7bGFzdHBhZ2V9ClxSZXF1aXJlUGFja2FnZXt0YWJ1bGFyeH0KXFJlcXVpcmVQ
YWNrYWdle3BzbGF0ZXh9ClxSZXF1aXJlUGFja2FnZXt0aW1lc30KXFJlcXVpcmVQYWNrYWdle3Zl
cmJhdGltfQpcUmVxdWlyZVBhY2thZ2V7Z2VvbWV0cnl9ClxSZXF1aXJlUGFja2FnZXt1cmx9Cgpc
dXNlcGFja2FnZVtoYW5nLGJmLHNtYWxsXXtjYXB0aW9ufQpcdXNlcGFja2FnZVtUMV17Zm9udGVu
Y30KXHVzZXBhY2thZ2Vbc2NhbGVkXXtoZWx2ZXR9ClxyZW5ld2NvbW1hbmQqXGZhbWlseWRlZmF1
bHR7XHNmZGVmYXVsdH0KClxuZXdpZlxpZnBkZgpcaWZ4XHBkZm91dHB1dFx1bmRlZmluZWQKICAg
ICAgICBccGRmZmFsc2UKICAgICAgICAlIFx0eXBlb3V0e1BERiBfbm90XyBkZWZpbmVkfQpcZWxz
ZQogICAgICAgIFxwZGZvdXRwdXQ9MQogICAgICAgIFxwZGZ0cnVlCiAgICAgICAgJSBcdHlwZW91
dHtQREYgX2lzXyBkZWZpbmVkfQpcZmkKClxpZnBkZgogICAgICAgIFx1c2VwYWNrYWdlW3BkZnRl
eCwKICAgICAgICAgICAgICAgIHBkZnBhZ2Vtb2RlPXtVc2VPdXRsaW5lc30sYm9va21hcmtzPXRy
dWUsYm9va21hcmtzb3Blbj10cnVlLAogICAgICAgICAgICAgICAgYm9va21hcmtzb3BlbmxldmVs
PTAsYm9va21hcmtzbnVtYmVyZWQ9dHJ1ZSwKICAgICAgICAgICAgICAgIGh5cGVydGV4bmFtZXM9
ZmFsc2UsY29sb3JsaW5rcyxsaW5rY29sb3I9e2JsdWV9LAogICAgICAgICAgICAgICAgY2l0ZWNv
bG9yPXtibHVlfSx1cmxjb2xvcj17cmVkfSwKICAgICAgICAgICAgICAgIHBkZnN0YXJ0dmlldz17
Rml0Vn1de2h5cGVycmVmfQpcZWxzZQogICAgICAgIFx1c2VwYWNrYWdlW2h5cGVydGV4XXtoeXBl
cnJlZn0KXGZpCiAgICAKXGlmcGRmCiAgICAgICAgXHVzZXBhY2thZ2VbcGRmdGV4XXtncmFwaGlj
eH0KICAgICAgICBccGRmY29tcHJlc3NsZXZlbCA5CiAgICAgICAgXHBkZmFkanVzdHNwYWNpbmcg
MQpcZWxzZQogICAgICAgIFx1c2VwYWNrYWdlW2R2aXBzXXtncmFwaGljeH0KXGZpCgpcdXNlcGFj
a2FnZXtjb2xvcn0KClxkZWZcZm9vdHNpemV7NW1tfQoKXGdlb21ldHJ5e2NlbnRlcmluZyxpbmNs
dWRlaGVhZGZvb3R9ClxnZW9tZXRyeXthNHBhcGVyLHRvcD0xNS41bW0saGVhZGhlaWdodD0yMG1t
LGhlYWRzZXA9NW1tLGZvb3Q9XGZvb3RzaXplLGZvb3Rza2lwPTEzLjNtbSxib3R0b209MTIuNW1t
fQpcZ2VvbWV0cnl7cmlnaHQ9MjVtbSxsZWZ0PTI1bW19CgoKCgoKCgoKXGRlZlxiaWJuYW1le1Jl
ZmVyZW5jZXN9Cgpcc2V0bGVuZ3Roe1xwYXJpbmRlbnR9ezBwdH0KXHNldGxlbmd0aHtccGFyc2tp
cH17MS40bW0gcGx1cyAwLjRtbSBtaW51cyAwLjJtbX0KClxkZWZcQGRlZmF1bHRmb290ZXJ7CiAg
XGRlZlxAb2RkZm9vdHtcdmJveCB0byBcZm9vdHNpemUgeyUKICAgIHtcY29sb3J7Ymx1ZX1caHJ1
bGUgd2lkdGggXHRleHR3aWR0aCBoZWlnaHQgMXB0IGRlcHRoIDBwdH0lCiAgICBcdmZpbAogICAg
JVxzbWFsbFxoYm94IHRvIFx0ZXh0d2lkdGh7XElTVE51bWJlciUKICAgIFxzbWFsbFxoYm94IHRv
IFx0ZXh0d2lkdGh7JQogICAgICAgICAgICAgICAgJVxoZmlsCiAgICAgICAgICAgICAgICAlXGhi
b3h7XGNvbG9yYm94e3llbGxvd317XE1ha2VVcHBlcmNhc2V7XEBEaXNzZW1pbmF0aW9ufX19JQog
ICAgICAgICAgICAgICAgXGhmaWwKICAgICAgICAgICAgICAgIFxoYm94e1x0aGVwYWdlL1xwYWdl
cmVme0xhc3RQYWdlfX19JQogICAgfSUKICB9JQp9CgoKXGRlZlxwc0B0aXRsZXslCiAgXEBkZWZh
dWx0Zm9vdGVyCiAgXGRlZlxAb2RkaGVhZHtcaGJveCB0byBcdGV4dHdpZHRoe1xFTUlMb2dvfX0K
JSAgXGRlZlxAb2RkaGVhZHtcaGJveCB0byBcdGV4dHdpZHRoe1xFTUlMb2dvXGhmaWxcTGFyZ2VD
RVNORVRMb2dvfX0KfQoKXGRlZlxwc0BoZWFkaW5nc3slCiAgXEBkZWZhdWx0Zm9vdGVyCiAgXGRl
ZlxAb2RkaGVhZHtcdmJveCB0byBcaGVhZGhlaWdodHslCiAgICAgIFx2Ym94IHRvIDAuNzVcaGVh
ZGhlaWdodHslCiAgICAgICAgXGhib3ggdG8gXHRleHR3aWR0aHslCiAgICAgICAgICBcaGJveCB0
byAwcHR7XEVNSUxvZ29caHNzfSUKICAgICAgICAgIFxoZmlsCgoKICAgICAgICAgXGhmaWwKClxo
Ym94IHRvIDBwdHtcaHNzXHZib3ggdG8gMC43NVxoZWFkaGVpZ2h0eyVcaHJ1bGUKXHNtYWxsClxw
YXJmaWxsc2tpcDBwdApcbGVmdHNraXAgMHB0IHBsdXMgMWZpbApccGFyc2tpcDBleApcdGV4dHNj
e1RpdGxlfToKXHBhcgpcdGV4dGJme1xAdGl0bGV9CgoKXHRleHRpdHtEYXRlfTogXHRleHRiZntc
QERhdGV9Clx2ZmlsCn19JQogICAgICAgIH0lCiAgICAgIH0lCiAgICAgIFx2ZmlsXHZza2lwIDIu
NW1tXHJlbGF4CiAgICAgIHtcY29sb3J7Ymx1ZX1caHJ1bGUgd2lkdGggXHRleHR3aWR0aCBoZWln
aHQgMXB0IGRlcHRoIDBwdH0lCiAgICB9JQogIH0lCn0KClxwYWdlc3R5bGV7aGVhZGluZ3N9Cgpc
c2V0bGVuZ3Roe1xjYXB0aW9ubWFyZ2lufXsxY219CgpcaWZwZGYKICAgICAgICBcRGVjbGFyZUdy
YXBoaWNzRXh0ZW5zaW9uc3suanBnLC5wZGYsLnBuZ30KICAgICAgICBccGRmY29tcHJlc3NsZXZl
bD05CglccGRmaW5mb3sgL1RpdGxlIChFTUkpIH0KXGVsc2UgICAKICAgICAgICBcRGVjbGFyZUdy
YXBoaWNzRXh0ZW5zaW9uc3suZXBzfQpcZmkKClxkZWZcZnJvbnRib3h3aWR0aHsxMWNtfSUKClxk
ZWZpbmVjb2xvcntNeVRlYWx9e3JnYn17MCwwLjQ2LDAuNDZ9ClxkZWZpbmVjb2xvcntibHVlfXty
Z2J9ezAuMDUsMC4yNiwwLjV9ClxkZWZpbmVjb2xvcntsaWdodGdyZXl9e2dyYXl9ezAuNjV9Cgpc
QXRCZWdpbkRvY3VtZW50ewpccGFnZXN0eWxle3RpdGxlfSUKXGhib3h7fSUgRm9yY2UgdG9wIG9m
IHBhZ2UKXHZmaWxsCntcY2VudGVyaW5nCiAgICAgICAgXGZvbnRzaXplezMwfXs1MH17XHRleHRi
ZntcdGV4dHNje1x0ZXh0Y29sb3J7Ymx1ZX17RXVyb3BlYW4gTWlkZGxld2FyZSBJbml0aWF0aXZl
fX19fVxcWzQwbW1dJQogICAgICAgICVcSHVnZXtcdGV4dGJme1x0ZXh0c2N7XHRleHRjb2xvcnti
bHVlfXtFdXJvcGVhbiBNaWRkbGV3YXJlIEluaXRpYXRpdmV9fX19XFxbMjBtbV0lCgogICAgICAg
IFxmb250c2l6ZXsyMn17Mjh9e1x0ZXh0YmZ7XHRleHRzY3tcQHRpdGxlfX19XFxbMm1tXSUKICAg
ICAgICAlXGlmeFxAU3VidGl0bGVcQGVtcHR5XGVsc2UKICAgICAgICAlICAgIFxub3JtYWxzaXpl
XHRleHRzZntcQFN1YnRpdGxlfVxcWzEwbW1dJQogICAgICAgICVcZmkKfQpcdmZpbGwKClxiZWdp
bntjZW50ZXJ9ClxoYm94IHRvIFx0ZXh0d2lkdGh7CiAgICAgCiAgICAgIFx2Ym94ewogICAgIAog
ICAgICB7XGNvbG9ye015VGVhbH1caHJ1bGUgd2lkdGggXGZyb250Ym94d2lkdGggaGVpZ2h0IDFt
bSBkZXB0aCAwcHR9ICAKICAgICAgCiAgICAgIFxoYm94IHRvIFxmcm9udGJveHdpZHRoe1xzZgog
ICAgICBcYmVnaW57dGFidWxhcnh9e1xmcm9udGJveHdpZHRofXtsPntccmFnZ2VkcmlnaHRcYXJy
YXliYWNrc2xhc2h9WH0gClxcIAogICAgICAgICAgICAgICAgRG9jdW1lbnQgdmVyc2lvbjogJiBc
dGV4dGJme1xARG9jVmVyc2lvbn1cXFszbW1dCiAgICAgICAgICAgICAgICBFTUkgQ29tcG9uZW50
IFZlcnNpb246ICYgXHRleHRiZntcQEVNSUNvbXBWZXJzaW9ufVxcWzNtbV0KICAgICAgICAgICAg
ICAgIERhdGU6ICYgXHRleHRiZntcQERhdGV9XFxbM21tXQogICAgICAgICAgICAgICAgJURvY3Vt
ZW50IHN0YXR1czogJiBcdGV4dGJme1xARG9jU3RhdHVzfVxcWzNtbV0KICAgICAgICAgICAgICAg
IAogICAgICBcZW5ke3RhYnVsYXJ4fQogIAogICAgIH0KICAgICAKICAgICAgIHtcY29sb3J7TXlU
ZWFsfVxocnVsZSB3aWR0aCBcZnJvbnRib3h3aWR0aCBoZWlnaHQgMW1tIGRlcHRoIDBwdH0KICAg
ICAlfSVjZW50ZXJpbmcKICAgICB9Cgp9ClxlbmR7Y2VudGVyfQoKXHZmaWxsClxuZXdwYWdlICAl
IGVuZCBvZiB0aGUgZmlyc3QgcGFnZQpccGFnZXN0eWxle2hlYWRpbmdzfQpcc2V0Y291bnRlcnt0
b2NkZXB0aH17M30KfSAlIEVuZCBvZiBBdEJlZ2lubmluZ0RvY3VtZW50CgoKXG5ld2NvbW1hbmR7
XHNlY3Rpb25icmVha317XG5ld3BhZ2V9CgpccmVuZXdjb21tYW5kXHNlY3Rpb257XEBzdGFydHNl
Y3Rpb24ge3NlY3Rpb259ezF9e1x6QH0lCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgey0zLjVleCBcQHBsdXMgLTFleCBcQG1pbnVzIC0uMmV4fSUKICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICB7Mi4zZXggXEBwbHVzLjJleH0lCiAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAge1xub3JtYWxmb250XExhcmdlXGJmc2VyaWVzXHNmZmFtaWx5XHNjc2hh
cGV9fQoKXHJlbmV3Y29tbWFuZFxzdWJzZWN0aW9ue1xAc3RhcnRzZWN0aW9ue3N1YnNlY3Rpb259
ezJ9e1x6QH0lCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7LTMuMjVleFxA
cGx1cyAtMWV4IFxAbWludXMgLS4yZXh9JQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgezEuNWV4IFxAcGx1cyAuMmV4fSUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgIHtcbm9ybWFsZm9udFxsYXJnZVxiZnNlcmllc1xzZmZhbWlseVxzY3NoYXBlfX0KXHJl
bmV3Y29tbWFuZFxzdWJzdWJzZWN0aW9ue1xAc3RhcnRzZWN0aW9ue3N1YnN1YnNlY3Rpb259ezN9
e1x6QH0lCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7LTMuMjVleFxAcGx1
cyAtMWV4IFxAbWludXMgLS4yZXh9JQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgezEuNWV4IFxAcGx1cyAuMmV4fSUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgIHtcbm9ybWFsZm9udFxub3JtYWxzaXplXGJmc2VyaWVzXHNmZmFtaWx5XHNjc2hhcGV9fQoK
CgoKCgpcbmV3c2F2ZWJveHtcQEVNSUxvZ299ClxzYXZlYm94e1xARU1JTG9nb317XGluY2x1ZGVn
cmFwaGljc1toZWlnaHQ9MC45NVxoZWFkaGVpZ2h0XXtFTUlfTG9nb19zdGR9fQpcZGVmXEVNSUxv
Z297XHVzZWJveHtcQEVNSUxvZ299fQpcZGVmXFNtYWxsRU1JTG9nb3tcaW5jbHVkZWdyYXBoaWNz
W2hlaWdodD1caGVhZGhlaWdodF17RU1JX0xvZ29fc3RkfX0KJVxkZWZcTGFyZ2VDRVNORVRMb2dv
e1xpbmNsdWRlZ3JhcGhpY3NbaGVpZ2h0PVxoZWFkaGVpZ2h0XXtjZXNuZXR9fQoKCgogICAgICAg
IApcZGVmXERvY1ZlcnNpb24jMXtcZ2RlZlxARG9jVmVyc2lvbnsjMX19ClxnZGVmXEBEb2NWZXJz
aW9ue1xAbGF0ZXhAd2FybmluZ0Bub0BsaW5le05vIFxub2V4cGFuZFxEb2NWZXJzaW9uIGdpdmVu
ICUKICAgICAgICAoZS5nLiAwLjEuMil9fQoKXGRlZlxFTUlDb21wVmVyc2lvbiMxe1xnZGVmXEBF
TUlDb21wVmVyc2lvbnsjMX19ClxnZGVmXEBFTUlDb21wVmVyc2lvbntcQGxhdGV4QHdhcm5pbmdA
bm9AbGluZXtObyBcbm9leHBhbmRcRU1JQ29tcFZlcnNpb24gZ2l2ZW4gJQogICAgICAgIChlLmcu
IDEuMi4zKX19CgpcZGVmXERhdGUjMXtcZ2RlZlxARGF0ZXsjMX19ClxnZGVmXEBEYXRle1xAbGF0
ZXhAd2FybmluZ0Bub0BsaW5le05vIFxub2V4cGFuZFxEYXRlIGdpdmVuICUKICAgICAgICAoZS5n
LiAwMS8wNC8yMDEwKX19CgoKCgoKClxsb25nXGRlZlxBYnN0cmFjdCMxe1xnZGVmXEBBYnN0cmFj
dHsjMX19ClxnZGVmXEBBYnN0cmFjdHtcQGxhdGV4QHdhcm5pbmdAbm9AbGluZXtObyBcbm9leHBh
bmRcQWJzdHJhY3QgZ2l2ZW59fQoKClx1cmxzdHlsZXtzZn0KXGlmcGRmCiAgXG5ld2NvbW1hbmR7
XEVtYWlsfVsxXXtcaHJlZnttYWlsdG86IzF9ezx7IzF9Pn19CiAgXG5ld2NvbW1hbmR7XEhUVFB9
WzFde1xocmVmeyMxfXtcdXJseyMxfX19ClxlbHNlCiAgXG5ld2NvbW1hbmR7XEVtYWlsfVsxXXtc
dGV4dHNmezx7IzF9Pn19CiAgXG5ld2NvbW1hbmR7XEhUVFB9WzFde1x1cmx7IzF9fQpcZmkKCgpc
ZGVmXEBwYXJ0WyMxXSMyeyUKICAgIFxpZm51bSBcY0BzZWNudW1kZXB0aCA+XG1AbmUKICAgICAg
XHJlZnN0ZXBjb3VudGVye3BhcnR9JQogICAgICBcYWRkY29udGVudHNsaW5le3RvY317cGFydH17
XHRoZXBhcnRcaHNwYWNlezFlbX1cdXBwZXJjYXNleyMxfX0lCiAgICBcZWxzZQogICAgICBcYWRk
Y29udGVudHNsaW5le3RvY317cGFydH17XHVwcGVyY2FzZXsjMX19JQogICAgXGZpCiAgICB7XHBh
cmluZGVudCBcekAgXHJhZ2dlZHJpZ2h0CiAgICAgXGludGVybGluZXBlbmFsdHkgXEBNCiAgICAg
XG5vcm1hbGZvbnQKICAgICBcaWZudW0gXGNAc2VjbnVtZGVwdGggPlxtQG5lCiAgICAgICBcTGFy
Z2VcYmZzZXJpZXMgXHBhcnRuYW1lXG5vYnJlYWtzcGFjZVx0aGVwYXJ0CiAgICAgICBccGFyXG5v
YnJlYWsKICAgICBcZmkKICAgICBcaHVnZSBcYmZzZXJpZXMgIzIlCiAgICAgXG1hcmtib3Roe317
fVxwYXJ9JQogICAgXG5vYnJlYWsKICAgIFx2c2tpcCAzZXgKICAgIFxAYWZ0ZXJoZWFkaW5nfQoK
XGRlZlxAc2VjdCMxIzIjMyM0IzUjNlsjN10jOHslCiAgXGlmbnVtICMyPlxjQHNlY251bWRlcHRo
CiAgICBcbGV0XEBzdnNlY1xAZW1wdHkKICBcZWxzZQogICAgXHJlZnN0ZXBjb3VudGVyeyMxfSUK
ICAgIFxwcm90ZWN0ZWRAZWRlZlxAc3ZzZWN7XEBzZWNjbnRmb3JtYXR7IzF9XHJlbGF4fSUKICBc
ZmkKICBcQHRlbXBza2lwYSAjNVxyZWxheAogIFxpZmRpbSBcQHRlbXBza2lwYT5cekAKICAgIFxi
ZWdpbmdyb3VwCiAgICAgICM2eyUKICAgICAgICBcQGhhbmdmcm9te1xoc2tpcCAjM1xyZWxheFxA
c3ZzZWN9JQogICAgICAgICAgXGludGVybGluZXBlbmFsdHkgXEBNICM4XEBAcGFyfSUKICAgIFxl
bmRncm91cAogICAgXGNzbmFtZSAjMW1hcmtcZW5kY3NuYW1le1x1cHBlcmNhc2V7Izd9fSUKICAg
IFxhZGRjb250ZW50c2xpbmV7dG9jfXsjMX17JQogICAgICBcaWZudW0gIzI+XGNAc2VjbnVtZGVw
dGggXGVsc2UKICAgICAgICBccHJvdGVjdFxudW1iZXJsaW5le1xjc25hbWUgdGhlIzFcZW5kY3Nu
YW1lfSUKICAgICAgXGZpCiAgICAgIFx0ZXhvcnBkZnN0cmluZ3tcdXBwZXJjYXNleyM3fX17Izd9
fSUKICBcZWxzZQogICAgXGRlZlxAc3ZzZWNoZHslCiAgICAgICM2e1xoc2tpcCAjM1xyZWxheAog
ICAgICBcQHN2c2VjICM4fSUKICAgICAgXGNzbmFtZSAjMW1hcmtcZW5kY3NuYW1le1x1cHBlcmNh
c2V7Izd9fSUKICAgICAgXGFkZGNvbnRlbnRzbGluZXt0b2N9eyMxfXslCiAgICAgICAgXGlmbnVt
ICMyPlxjQHNlY251bWRlcHRoIFxlbHNlCiAgICAgICAgICBccHJvdGVjdFxudW1iZXJsaW5le1xj
c25hbWUgdGhlIzFcZW5kY3NuYW1lfSUKICAgICAgICBcZmkKICAgICAgICBcdGV4b3JwZGZzdHJp
bmd7XHVwcGVyY2FzZXsjN319eyM3fX19JQogIFxmaQogIFxAeHNlY3R7IzV9fQoKClxkZWZcbEBw
YXJ0e1xAZG90dGVkdG9jbGluZXsxfXs0ZW19ezIuMGVtfX0KXGRlZlxsQHN1YnNlY3Rpb257XEBk
b3R0ZWR0b2NsaW5lezJ9ezEuNWVtfXsyLjNlbX19ClxkZWZcbEBzdWJzdWJzZWN0aW9ue1xAZG90
dGVkdG9jbGluZXszfXszLjhlbX17My4yZW19fQpcZGVmXGxAcGFyYWdyYXBoe1xAZG90dGVkdG9j
bGluZXs0fXs3LjBlbX17NC4xZW19fQpcZGVmXGxAc3VicGFyYWdyYXBoe1xAZG90dGVkdG9jbGlu
ZXs1fXsxMGVtfXs1ZW19fQoK};

	close T;

	system("base64 -d -i emi.cls.b64 > emi.cls");
	system("rm emi.cls.b64");

}

sub gen_emi_logo {
	open T,">EMI_Logo_std.pdf.b64" or die "EMI_Logo_std.pdf.b64: $!\n";

	print T q{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
TY6W7LvXqoyBR7Lvx62v29i78f2XDqmTJfNp5t0B8IGYbYt8lBfTuX1xFoyOrOCvV7oBK/Qbde7I
Cv16pRuwyUgf/R35Smq6nf/RZ03mutdf8P//C2FSev5lbmRzdHJlYW0KZW5kb2JqCjcgMCBvYmoK
NTQ5MwplbmRvYmoKNSAwIG9iago8PC9UeXBlL1BhZ2UvTWVkaWFCb3ggWzAgMCAyNzIuMjkgMTE4
LjM5XQovUGFyZW50IDMgMCBSCi9SZXNvdXJjZXM8PC9Qcm9jU2V0Wy9QREZdCi9Db2xvclNwYWNl
IDc5IDAgUgovRXh0R1N0YXRlIDgwIDAgUgovUGF0dGVybiA4MSAwIFIKL1NoYWRpbmcgODIgMCBS
Cj4+Ci9Db250ZW50cyA2IDAgUgo+PgplbmRvYmoKMyAwIG9iago8PCAvVHlwZSAvUGFnZXMgL0tp
ZHMgWwo1IDAgUgpdIC9Db3VudCAxCj4+CmVuZG9iagoxIDAgb2JqCjw8L1R5cGUgL0NhdGFsb2cg
L1BhZ2VzIDMgMCBSCi9NZXRhZGF0YSA4MyAwIFIKPj4KZW5kb2JqCjggMCBvYmoKPDwvVHlwZS9F
eHRHU3RhdGUKL09QTSAxPj5lbmRvYmoKOSAwIG9iagpbL1BhdHRlcm5dCmVuZG9iagoxNSAwIG9i
ago8PC9UeXBlL0V4dEdTdGF0ZQovU0EgdHJ1ZT4+ZW5kb2JqCjQgMCBvYmoKPDwvRmlsdGVyL0Zs
YXRlRGVjb2RlCi9UeXBlL01ldGFkYXRhCi9TdWJ0eXBlL1hNTC9MZW5ndGggMTU3ODc+PnN0cmVh
bQp4nJy819LrSpI1dj9PceL8EbqBpuFda7r/AAkQhnCEIcwdLOE9QACvpgs9kl5BxY/79HT335oJ
iRHk3psoJMpkrlwrq7j/43/uQ5TU2fJbnL3K7i+//9//5//1+29l+pffPVJDtOGaFaV0Tpl96k5y
1gmb/v4///pv/7H/eW+HNlui3/a26eY/73/5PUr7OPsz+Pvna/j3336aLPVffuc+F37zNfO3az9l
vxF/wv6E/XuCUPhvJP4nnERpnPzff8MQhIERGsawf0eZP6Pon1Hst1+v3//6b+DzP6Y0/7PF3349
EPzrL78XyzL8GYbf7/ef3vif+ukFoyzLwgj2MQNa/Pt8dEu0/3s3/4+vkT/s8NmcTOWwlH332+ff
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
CmVuZHN0cmVhbQplbmRvYmoKNzkgMCBvYmoKPDwvUjkKOSAwIFI+PgplbmRvYmoKODAgMCBvYmoK
PDwvUjE1CjE1IDAgUi9SOAo4IDAgUj4+CmVuZG9iago4MSAwIG9iago8PC9SNzcKNzcgMCBSL1I3
NQo3NSAwIFIvUjczCjczIDAgUi9SNzEKNzEgMCBSL1I2OQo2OSAwIFIvUjY3CjY3IDAgUi9SNjUK
NjUgMCBSL1I2Mwo2MyAwIFIvUjYxCjYxIDAgUi9SNTkKNTkgMCBSL1I1Nwo1NyAwIFIvUjU1CjU1
IDAgUi9SNTMKNTMgMCBSL1I1MQo1MSAwIFIvUjQ5CjQ5IDAgUi9SNDcKNDcgMCBSL1I0NQo0NSAw
IFIvUjQzCjQzIDAgUi9SNDEKNDEgMCBSL1IzOQozOSAwIFIvUjM3CjM3IDAgUi9SMzUKMzUgMCBS
L1IzMwozMyAwIFIvUjMxCjMxIDAgUi9SMjkKMjkgMCBSL1IyNwoyNyAwIFIvUjI1CjI1IDAgUi9S
MjAKMjAgMCBSL1IxOAoxOCAwIFIvUjE2CjE2IDAgUi9SMTAKMTAgMCBSPj4KZW5kb2JqCjc3IDAg
b2JqCjw8L1BhdHRlcm5UeXBlIDIKL1NoYWRpbmcgNzggMCBSCi9NYXRyaXhbLTAuMDAwMDAwOTAK
LTIwLjY4NzUKLTIwLjY4NzUKMC4wMDAwMDA5MAoxMzkuODA0CjE1Ljk1N10+PmVuZG9iago3NSAw
IG9iago8PC9QYXR0ZXJuVHlwZSAyCi9TaGFkaW5nIDc2IDAgUgovTWF0cml4Wy0wLjAwMDAwMDkw
Ci0yMC42ODc1Ci0yMC42ODc1CjAuMDAwMDAwOTAKMTM5LjgwNAoxNS45NTddPj5lbmRvYmoKNzMg
MCBvYmoKPDwvUGF0dGVyblR5cGUgMgovU2hhZGluZyA3NCAwIFIKL01hdHJpeFstMC4wMDAwMDA5
MAotMjAuNjg3NQotMjAuNjg3NQowLjAwMDAwMDkwCjEzOS44MDQKMTUuOTU3XT4+ZW5kb2JqCjcx
IDAgb2JqCjw8L1BhdHRlcm5UeXBlIDIKL1NoYWRpbmcgNzIgMCBSCi9NYXRyaXhbLTAuMDAwMDAw
OTAKLTIwLjY4NzUKLTIwLjY4NzUKMC4wMDAwMDA5MAoxMzkuODA0CjE1Ljk1N10+PmVuZG9iago2
OSAwIG9iago8PC9QYXR0ZXJuVHlwZSAyCi9TaGFkaW5nIDcwIDAgUgovTWF0cml4Wy0wLjAwMDAw
MDkwCi0yMC42ODc1Ci0yMC42ODc1CjAuMDAwMDAwOTAKMTM5LjgwNAoxNS45NTddPj5lbmRvYmoK
NjcgMCBvYmoKPDwvUGF0dGVyblR5cGUgMgovU2hhZGluZyA2OCAwIFIKL01hdHJpeFstMC4wMDAw
MDA5MAotMjAuNjg3NQotMjAuNjg3NQowLjAwMDAwMDkwCjEzOS44MDQKMTUuOTU3XT4+ZW5kb2Jq
CjY1IDAgb2JqCjw8L1BhdHRlcm5UeXBlIDIKL1NoYWRpbmcgNjYgMCBSCi9NYXRyaXhbLTAuMDAw
MDAwOTAKLTIwLjY4NzUKLTIwLjY4NzUKMC4wMDAwMDA5MAoxMzkuODA0CjE1Ljk1N10+PmVuZG9i
ago2MyAwIG9iago8PC9QYXR0ZXJuVHlwZSAyCi9TaGFkaW5nIDY0IDAgUgovTWF0cml4Wy0wLjAw
MDAwMDkwCi0yMC42ODc1Ci0yMC42ODc1CjAuMDAwMDAwOTAKMTM5LjgwNAoxNS45NTddPj5lbmRv
YmoKNjEgMCBvYmoKPDwvUGF0dGVyblR5cGUgMgovU2hhZGluZyA2MiAwIFIKL01hdHJpeFstMC4w
MDAwMDA5MAotMjAuNjg3NQotMjAuNjg3NQowLjAwMDAwMDkwCjEzOS44MDQKMTUuOTU3XT4+ZW5k
b2JqCjU5IDAgb2JqCjw8L1BhdHRlcm5UeXBlIDIKL1NoYWRpbmcgNjAgMCBSCi9NYXRyaXhbLTAu
MDAwMDAwOTAKLTIwLjY4NzUKLTIwLjY4NzUKMC4wMDAwMDA5MAoxMzkuODA0CjE1Ljk1N10+PmVu
ZG9iago1NyAwIG9iago8PC9QYXR0ZXJuVHlwZSAyCi9TaGFkaW5nIDU4IDAgUgovTWF0cml4Wy0w
LjAwMDAwMDkwCi0yMC42ODc1Ci0yMC42ODc1CjAuMDAwMDAwOTAKMTM5LjgwNAoxNS45NTddPj5l
bmRvYmoKNTUgMCBvYmoKPDwvUGF0dGVyblR5cGUgMgovU2hhZGluZyA1NiAwIFIKL01hdHJpeFst
MC4wMDAwMDA5MAotMjAuNjg3NQotMjAuNjg3NQowLjAwMDAwMDkwCjEzOS44MDQKMTUuOTU3XT4+
ZW5kb2JqCjUzIDAgb2JqCjw8L1BhdHRlcm5UeXBlIDIKL1NoYWRpbmcgNTQgMCBSCi9NYXRyaXhb
LTAuMDAwMDAwOTAKLTIwLjY4NzUKLTIwLjY4NzUKMC4wMDAwMDA5MAoxMzkuODA0CjE1Ljk1N10+
PmVuZG9iago1MSAwIG9iago8PC9QYXR0ZXJuVHlwZSAyCi9TaGFkaW5nIDUyIDAgUgovTWF0cml4
Wy0wLjAwMDAwMDkwCi0yMC42ODc1Ci0yMC42ODc1CjAuMDAwMDAwOTAKMTM5LjgwNAoxNS45NTdd
Pj5lbmRvYmoKNDkgMCBvYmoKPDwvUGF0dGVyblR5cGUgMgovU2hhZGluZyA1MCAwIFIKL01hdHJp
eFstMC4wMDAwMDA5MAotMjAuNjg3NQotMjAuNjg3NQowLjAwMDAwMDkwCjEzOS44MDQKMTUuOTU3
XT4+ZW5kb2JqCjQ3IDAgb2JqCjw8L1BhdHRlcm5UeXBlIDIKL1NoYWRpbmcgNDggMCBSCi9NYXRy
aXhbLTAuMDAwMDAwOTAKLTIwLjY4NzUKLTIwLjY4NzUKMC4wMDAwMDA5MAoxMzkuODA0CjE1Ljk1
N10+PmVuZG9iago0NSAwIG9iago8PC9QYXR0ZXJuVHlwZSAyCi9TaGFkaW5nIDQ2IDAgUgovTWF0
cml4Wy0wLjAwMDAwMDkwCi0yMC42ODc1Ci0yMC42ODc1CjAuMDAwMDAwOTAKMTM5LjgwNAoxNS45
NTddPj5lbmRvYmoKNDMgMCBvYmoKPDwvUGF0dGVyblR5cGUgMgovU2hhZGluZyA0NCAwIFIKL01h
dHJpeFstMC4wMDAwMDA5MAotMjAuNjg3NQotMjAuNjg3NQowLjAwMDAwMDkwCjEzOS44MDQKMTUu
OTU3XT4+ZW5kb2JqCjQxIDAgb2JqCjw8L1BhdHRlcm5UeXBlIDIKL1NoYWRpbmcgNDIgMCBSCi9N
YXRyaXhbLTAuMDAwMDAwOTAKLTIwLjY4NzUKLTIwLjY4NzUKMC4wMDAwMDA5MAoxMzkuODA0CjE1
Ljk1N10+PmVuZG9iagozOSAwIG9iago8PC9QYXR0ZXJuVHlwZSAyCi9TaGFkaW5nIDQwIDAgUgov
TWF0cml4Wy0wLjAwMDAwMDkwCi0yMC42ODc1Ci0yMC42ODc1CjAuMDAwMDAwOTAKMTM5LjgwNAox
NS45NTddPj5lbmRvYmoKMzcgMCBvYmoKPDwvUGF0dGVyblR5cGUgMgovU2hhZGluZyAzOCAwIFIK
L01hdHJpeFstMC4wMDAwMDA5MAotMjAuNjg3NQotMjAuNjg3NQowLjAwMDAwMDkwCjEzOS44MDQK
MTUuOTU3XT4+ZW5kb2JqCjM1IDAgb2JqCjw8L1BhdHRlcm5UeXBlIDIKL1NoYWRpbmcgMzYgMCBS
Ci9NYXRyaXhbLTAuMDAwMDAwOTAKLTIwLjY4NzUKLTIwLjY4NzUKMC4wMDAwMDA5MAoxMzkuODA0
CjE1Ljk1N10+PmVuZG9iagozMyAwIG9iago8PC9QYXR0ZXJuVHlwZSAyCi9TaGFkaW5nIDM0IDAg
UgovTWF0cml4Wy0wLjAwMDAwMDkwCi0yMC42ODc1Ci0yMC42ODc1CjAuMDAwMDAwOTAKMTM5Ljgw
NAoxNS45NTddPj5lbmRvYmoKMzEgMCBvYmoKPDwvUGF0dGVyblR5cGUgMgovU2hhZGluZyAzMiAw
IFIKL01hdHJpeFstMC4wMDAwMDA5MAotMjAuNjg3NQotMjAuNjg3NQowLjAwMDAwMDkwCjEzOS44
MDQKMTUuOTU3XT4+ZW5kb2JqCjI5IDAgb2JqCjw8L1BhdHRlcm5UeXBlIDIKL1NoYWRpbmcgMzAg
MCBSCi9NYXRyaXhbLTAuMDAwMDAwOTAKLTIwLjY4NzUKLTIwLjY4NzUKMC4wMDAwMDA5MAoxMzku
ODA0CjE1Ljk1N10+PmVuZG9iagoyNyAwIG9iago8PC9QYXR0ZXJuVHlwZSAyCi9TaGFkaW5nIDI4
IDAgUgovTWF0cml4Wy0wLjAwMDAwMDkwCi0yMC42ODc1Ci0yMC42ODc1CjAuMDAwMDAwOTAKMTM5
LjgwNAoxNS45NTddPj5lbmRvYmoKMjUgMCBvYmoKPDwvUGF0dGVyblR5cGUgMgovU2hhZGluZyAy
NiAwIFIKL01hdHJpeFstMC4wMDAwMDA5MAotMjAuNjg3NQotMjAuNjg3NQowLjAwMDAwMDkwCjEz
OS44MDQKMTUuOTU3XT4+ZW5kb2JqCjIwIDAgb2JqCjw8L1BhdHRlcm5UeXBlIDIKL1NoYWRpbmcg
MjEgMCBSCi9NYXRyaXhbLTAuMDAwMDAwOTAKLTIwLjY4NzUKLTIwLjY4NzUKMC4wMDAwMDA5MAox
MzkuODA0CjE1Ljk1N10+PmVuZG9iagoxOCAwIG9iago8PC9QYXR0ZXJuVHlwZSAyCi9TaGFkaW5n
IDE5IDAgUgovTWF0cml4Wy0wLjAwMDAwNDIzCjk2Ljc1Cjk2Ljc1CjAuMDAwMDA0MjMKMzYuNzM3
MwoyMS4xNF0+PmVuZG9iagoxNiAwIG9iago8PC9QYXR0ZXJuVHlwZSAyCi9TaGFkaW5nIDE3IDAg
UgovTWF0cml4Wy0wLjAwMDAwNDIzCjk2Ljc0OTUKOTYuNzQ5NQowLjAwMDAwNDIzCjE0MC4xNTkK
MjEuMTRdPj5lbmRvYmoKMTAgMCBvYmoKPDwvUGF0dGVyblR5cGUgMgovU2hhZGluZyAxMSAwIFIK
L01hdHJpeFstMC4wMDAwMDQyNQo5Ny4xODkKOTcuMTg5CjAuMDAwMDA0MjUKMjM4Ljk3MgoyMC45
NTA1XT4+ZW5kb2JqCjgyIDAgb2JqCjw8L1I3OAo3OCAwIFIvUjc2Cjc2IDAgUi9SNzQKNzQgMCBS
L1I3Mgo3MiAwIFIvUjcwCjcwIDAgUi9SNjgKNjggMCBSL1I2Ngo2NiAwIFIvUjY0CjY0IDAgUi9S
NjIKNjIgMCBSL1I2MAo2MCAwIFIvUjU4CjU4IDAgUi9SNTYKNTYgMCBSL1I1NAo1NCAwIFIvUjUy
CjUyIDAgUi9SNTAKNTAgMCBSL1I0OAo0OCAwIFIvUjQ2CjQ2IDAgUi9SNDQKNDQgMCBSL1I0Mgo0
MiAwIFIvUjQwCjQwIDAgUi9SMzgKMzggMCBSL1IzNgozNiAwIFIvUjM0CjM0IDAgUi9SMzIKMzIg
MCBSL1IzMAozMCAwIFIvUjI4CjI4IDAgUi9SMjYKMjYgMCBSL1IyMQoyMSAwIFIvUjE5CjE5IDAg
Ui9SMTcKMTcgMCBSL1IxMQoxMSAwIFI+PgplbmRvYmoKNzggMCBvYmoKPDwvU2hhZGluZ1R5cGUg
MgovQ29sb3JTcGFjZS9EZXZpY2VDTVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAg
UgovRXh0ZW5kIFt0cnVlIHRydWVdPj5lbmRvYmoKNzYgMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgov
Q29sb3JTcGFjZS9EZXZpY2VDTVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgov
RXh0ZW5kIFt0cnVlIHRydWVdPj5lbmRvYmoKNzQgMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29s
b3JTcGFjZS9EZXZpY2VDTVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0
ZW5kIFt0cnVlIHRydWVdPj5lbmRvYmoKNzIgMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JT
cGFjZS9EZXZpY2VDTVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0ZW5k
IFt0cnVlIHRydWVdPj5lbmRvYmoKNzAgMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFj
ZS9EZXZpY2VDTVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0ZW5kIFt0
cnVlIHRydWVdPj5lbmRvYmoKNjggMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9E
ZXZpY2VDTVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0ZW5kIFt0cnVl
IHRydWVdPj5lbmRvYmoKNjYgMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9EZXZp
Y2VDTVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0ZW5kIFt0cnVlIHRy
dWVdPj5lbmRvYmoKNjQgMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9EZXZpY2VD
TVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0ZW5kIFt0cnVlIHRydWVd
Pj5lbmRvYmoKNjIgMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9EZXZpY2VDTVlL
Ci9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0ZW5kIFt0cnVlIHRydWVdPj5l
bmRvYmoKNjAgMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9EZXZpY2VDTVlLCi9D
b29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0ZW5kIFt0cnVlIHRydWVdPj5lbmRv
YmoKNTggMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9EZXZpY2VDTVlLCi9Db29y
ZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0ZW5kIFt0cnVlIHRydWVdPj5lbmRvYmoK
NTYgMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9EZXZpY2VDTVlLCi9Db29yZHNb
MAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0ZW5kIFt0cnVlIHRydWVdPj5lbmRvYmoKNTQg
MCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9EZXZpY2VDTVlLCi9Db29yZHNbMAow
CjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0ZW5kIFt0cnVlIHRydWVdPj5lbmRvYmoKNTIgMCBv
YmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9EZXZpY2VDTVlLCi9Db29yZHNbMAowCjEK
MF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0ZW5kIFt0cnVlIHRydWVdPj5lbmRvYmoKNTAgMCBvYmoK
PDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9EZXZpY2VDTVlLCi9Db29yZHNbMAowCjEKMF0K
L0Z1bmN0aW9uIDI0IDAgUgovRXh0ZW5kIFt0cnVlIHRydWVdPj5lbmRvYmoKNDggMCBvYmoKPDwv
U2hhZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9EZXZpY2VDTVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1
bmN0aW9uIDI0IDAgUgovRXh0ZW5kIFt0cnVlIHRydWVdPj5lbmRvYmoKNDYgMCBvYmoKPDwvU2hh
ZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9EZXZpY2VDTVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0
aW9uIDI0IDAgUgovRXh0ZW5kIFt0cnVlIHRydWVdPj5lbmRvYmoKNDQgMCBvYmoKPDwvU2hhZGlu
Z1R5cGUgMgovQ29sb3JTcGFjZS9EZXZpY2VDTVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9u
IDI0IDAgUgovRXh0ZW5kIFt0cnVlIHRydWVdPj5lbmRvYmoKNDIgMCBvYmoKPDwvU2hhZGluZ1R5
cGUgMgovQ29sb3JTcGFjZS9EZXZpY2VDTVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0
IDAgUgovRXh0ZW5kIFt0cnVlIHRydWVdPj5lbmRvYmoKNDAgMCBvYmoKPDwvU2hhZGluZ1R5cGUg
MgovQ29sb3JTcGFjZS9EZXZpY2VDTVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAg
UgovRXh0ZW5kIFt0cnVlIHRydWVdPj5lbmRvYmoKMzggMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgov
Q29sb3JTcGFjZS9EZXZpY2VDTVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgov
RXh0ZW5kIFt0cnVlIHRydWVdPj5lbmRvYmoKMzYgMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29s
b3JTcGFjZS9EZXZpY2VDTVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0
ZW5kIFt0cnVlIHRydWVdPj5lbmRvYmoKMzQgMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JT
cGFjZS9EZXZpY2VDTVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0ZW5k
IFt0cnVlIHRydWVdPj5lbmRvYmoKMzIgMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFj
ZS9EZXZpY2VDTVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0ZW5kIFt0
cnVlIHRydWVdPj5lbmRvYmoKMzAgMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9E
ZXZpY2VDTVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0ZW5kIFt0cnVl
IHRydWVdPj5lbmRvYmoKMjggMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9EZXZp
Y2VDTVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0ZW5kIFt0cnVlIHRy
dWVdPj5lbmRvYmoKMjYgMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9EZXZpY2VD
TVlLCi9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0ZW5kIFt0cnVlIHRydWVd
Pj5lbmRvYmoKMjEgMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9EZXZpY2VDTVlL
Ci9Db29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDI0IDAgUgovRXh0ZW5kIFt0cnVlIHRydWVdPj5l
bmRvYmoKMTkgMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9EZXZpY2VDTVlLCi9D
b29yZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDE0IDAgUgovRXh0ZW5kIFt0cnVlIHRydWVdPj5lbmRv
YmoKMTcgMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9EZXZpY2VDTVlLCi9Db29y
ZHNbMAowCjEKMF0KL0Z1bmN0aW9uIDE0IDAgUgovRXh0ZW5kIFt0cnVlIHRydWVdPj5lbmRvYmoK
MTEgMCBvYmoKPDwvU2hhZGluZ1R5cGUgMgovQ29sb3JTcGFjZS9EZXZpY2VDTVlLCi9Db29yZHNb
MAowCjEKMF0KL0Z1bmN0aW9uIDE0IDAgUgovRXh0ZW5kIFt0cnVlIHRydWVdPj5lbmRvYmoKMjMg
MCBvYmoKPDwvRmlsdGVyL0ZsYXRlRGVjb2RlCi9GdW5jdGlvblR5cGUgMAovRG9tYWluWzAKMV0K
L1JhbmdlWzAKMQowCjEKMAoxCjAKMV0KL0JpdHNQZXJTYW1wbGUgOAovRW5jb2RlWzAKNjNdCi9E
ZWNvZGVbMAoxCjAKMQowCjEKMAoxXQovU2l6ZVs2NF0vTGVuZ3RoIDE1Pj5zdHJlYW0KeJx7d6R1
8bsRjAHFlbaBCmVuZHN0cmVhbQplbmRvYmoKMjIgMCBvYmoKPDwvRmlsdGVyL0ZsYXRlRGVjb2Rl
Ci9GdW5jdGlvblR5cGUgMAovRG9tYWluWzAKMV0KL1JhbmdlWzAKMQowCjEKMAoxCjAKMV0KL0Jp
dHNQZXJTYW1wbGUgOAovRW5jb2RlWzAKNjNdCi9EZWNvZGVbMAoxCjAKMQowCjEKMAoxXQovU2l6
ZVs2NF0vTGVuZ3RoIDIzOT4+c3RyZWFtCnicDcMPLwJxGAfw92VmZmbMzMwMSZIkSZKUc9V1V6yZ
GTMM8yfeyu+6iHue3kh/yP/x9Xy2T0Pt3DdkUxXvZLmpCuWWKty2lHXTtq3rtm1evdjm5Wslf9Gp
5M87jnH25hin707u5KOaPf6sZo++HjKH34/6wU9N3/+tbe/9PWklPGu7cLeKcNMW3JQJd9MAJXOg
jYzUQQkNtJ4GxVOgtaRMgGNx8GpMRsHRiAyDV0IyCI4EpB/1ZZ/0oh72gJemwKFJ8OIEODgOXhgD
B0bB8yNyGOwfAs8Ngn0DoNl+2Qfy9oJmekCebrjTXf/QGasiCmVuZHN0cmVhbQplbmRvYmoKMjQg
MCBvYmoKPDwvRnVuY3Rpb25zWzIyIDAgUgoyMyAwIFJdCi9GdW5jdGlvblR5cGUgMwovRG9tYWlu
WzAKMV0KL0JvdW5kc1swLjg3MjcyN10KL0VuY29kZVsxCjAKMAoxXT4+ZW5kb2JqCjEzIDAgb2Jq
Cjw8L0ZpbHRlci9GbGF0ZURlY29kZQovRnVuY3Rpb25UeXBlIDAKL0RvbWFpblswCjFdCi9SYW5n
ZVswCjEKMAoxCjAKMQowCjFdCi9CaXRzUGVyU2FtcGxlIDgKL0VuY29kZVswCjYzXQovRGVjb2Rl
WzAKMQowCjEKMAoxCjAKMV0KL1NpemVbNjRdL0xlbmd0aCAyNjc+PnN0cmVhbQp4nAEAAf/+7sSF
o+7EhaPuw4Wi78OEou/EhKHwxIOg8MSDnvHEgp3yxIGb88SBmfTFgJf1xYCV98Z/k/nHfpD6x32N
/Mh8i/7JfIj/yXuF/8l6g//JeYD/yXh+/8h2e//IdXn/yHR2/8dzc//HcnD/x3Js/8dxaf/HcGX/
x29j/8ZuYP/GbF3/xWta/8RqV//DaFP/w2dQ/8JmTP/CZEn/wWNG/8BhQ/+/YD//vl48/71cOf+8
Wjb/u1kz/7lXMP+4VS3+tlQq/bVSJ/20TyT8sk0h+7BLHvquSRz5rEcZ96pFF/aoQxT1pkAS9aQ+
EPSiOw7ynzkM8Z02Cu+aNAnulzEH7ZUvBnMfnRcKZW5kc3RyZWFtCmVuZG9iagoxMiAwIG9iago8
PC9GaWx0ZXIvRmxhdGVEZWNvZGUKL0Z1bmN0aW9uVHlwZSAwCi9Eb21haW5bMAoxXQovUmFuZ2Vb
MAoxCjAKMQowCjEKMAoxXQovQml0c1BlclNhbXBsZSA4Ci9FbmNvZGVbMAo2M10KL0RlY29kZVsw
CjEKMAoxCjAKMQowCjFdCi9TaXplWzY0XS9MZW5ndGggMjMxPj5zdHJlYW0KeJwNwwsvgnEUB+Dv
pbGMsRpjTNNFSrqolC7S201vYrPWmpmZGbP6Km8l9D+nL1IyuYz5Oc/2QNmnQA4TyDktZ0Aus5wF
bc3JebB7Aby9KC1gjxXsXZLL4J0VsG9VroF318H+DXDAJjfBQTsGIScGey7pBoc90guO+KRfBsHR
kAyD96MyBo7FZQIUT4EO0jIDSmRBSQ2UyoPSBdBhCSpThjrSobIVKK2Kvnb295I7/33O1X6e8vXv
XqHx1StefD4WLz+6patJ9/j6vVO+eevot+O2fjduV+5fjZOHkVFtDo3T1j9t4KkGCmVuZHN0cmVh
bQplbmRvYmoKMTQgMCBvYmoKPDwvRnVuY3Rpb25zWzEyIDAgUgoxMyAwIFJdCi9GdW5jdGlvblR5
cGUgMwovRG9tYWluWzAKMV0KL0JvdW5kc1swLjUyNzI2N10KL0VuY29kZVswCjEKMAoxXT4+ZW5k
b2JqCjgzIDAgb2JqCjw8L1R5cGUvTWV0YWRhdGEKL1N1YnR5cGUvWE1ML0xlbmd0aCAxMzE5Pj5z
dHJlYW0KPD94cGFja2V0IGJlZ2luPSfvu78nIGlkPSdXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQn
Pz4KPD9hZG9iZS14YXAtZmlsdGVycyBlc2M9IkNSTEYiPz4KPHg6eG1wbWV0YSB4bWxuczp4PSdh
ZG9iZTpuczptZXRhLycgeDp4bXB0az0nWE1QIHRvb2xraXQgMi45LjEtMTMsIGZyYW1ld29yayAx
LjYnPgo8cmRmOlJERiB4bWxuczpyZGY9J2h0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRm
LXN5bnRheC1ucyMnIHhtbG5zOmlYPSdodHRwOi8vbnMuYWRvYmUuY29tL2lYLzEuMC8nPgo8cmRm
OkRlc2NyaXB0aW9uIHJkZjphYm91dD0nMzFkMWMwNjktOGYxMC0xMWViLTAwMDAtM2VlNDM2OTQw
ZjQ5JyB4bWxuczpwZGY9J2h0dHA6Ly9ucy5hZG9iZS5jb20vcGRmLzEuMy8nIHBkZjpQcm9kdWNl
cj0nR1BMIEdob3N0c2NyaXB0IDguNzEnLz4KPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JzMx
ZDFjMDY5LThmMTAtMTFlYi0wMDAwLTNlZTQzNjk0MGY0OScgeG1sbnM6eG1wPSdodHRwOi8vbnMu
YWRvYmUuY29tL3hhcC8xLjAvJz48eG1wOk1vZGlmeURhdGU+MjAxMS0wMy0yNVQxNjoyMjowNysw
MTowMDwveG1wOk1vZGlmeURhdGU+Cjx4bXA6Q3JlYXRlRGF0ZT4yMDExLTAzLTI1VDE2OjIyOjA3
KzAxOjAwPC94bXA6Q3JlYXRlRGF0ZT4KPHhtcDpDcmVhdG9yVG9vbD5Vbmtub3duQXBwbGljYXRp
b248L3htcDpDcmVhdG9yVG9vbD48L3JkZjpEZXNjcmlwdGlvbj4KPHJkZjpEZXNjcmlwdGlvbiBy
ZGY6YWJvdXQ9JzMxZDFjMDY5LThmMTAtMTFlYi0wMDAwLTNlZTQzNjk0MGY0OScgeG1sbnM6eGFw
TU09J2h0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8nIHhhcE1NOkRvY3VtZW50SUQ9JzMx
ZDFjMDY5LThmMTAtMTFlYi0wMDAwLTNlZTQzNjk0MGY0OScvPgo8cmRmOkRlc2NyaXB0aW9uIHJk
ZjphYm91dD0nMzFkMWMwNjktOGYxMC0xMWViLTAwMDAtM2VlNDM2OTQwZjQ5JyB4bWxuczpkYz0n
aHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8nIGRjOmZvcm1hdD0nYXBwbGljYXRpb24v
cGRmJz48ZGM6dGl0bGU+PHJkZjpBbHQ+PHJkZjpsaSB4bWw6bGFuZz0neC1kZWZhdWx0Jz5VbnRp
dGxlZDwvcmRmOmxpPjwvcmRmOkFsdD48L2RjOnRpdGxlPjwvcmRmOkRlc2NyaXB0aW9uPgo8L3Jk
ZjpSREY+CjwveDp4bXBtZXRhPgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCjw/eHBh
Y2tldCBlbmQ9J3cnPz4KZW5kc3RyZWFtCmVuZG9iagoyIDAgb2JqCjw8L1Byb2R1Y2VyKEdQTCBH
aG9zdHNjcmlwdCA4LjcxKQovQ3JlYXRpb25EYXRlKEQ6MjAxMTAzMjUxNjIyMDcrMDEnMDAnKQov
TW9kRGF0ZShEOjIwMTEwMzI1MTYyMjA3KzAxJzAwJyk+PmVuZG9iagp4cmVmCjAgODQKMDAwMDAw
MDAwMCA2NTUzNSBmIAowMDAwMDA1ODQ2IDAwMDAwIG4gCjAwMDAwMzI4MDcgMDAwMDAgbiAKMDAw
MDAwNTc4NyAwMDAwMCBuIAowMDAwMDA2MDIyIDAwMDAwIG4gCjAwMDAwMDU1OTggMDAwMDAgbiAK
MDAwMDAwMDAxNSAwMDAwMCBuIAowMDAwMDA1NTc4IDAwMDAwIG4gCjAwMDAwMDU5MTEgMDAwMDAg
biAKMDAwMDAwNTk1MiAwMDAwMCBuIAowMDAwMDI1Nzc5IDAwMDAwIG4gCjAwMDAwMjk1ODMgMDAw
MDAgbiAKMDAwMDAzMDg4NCAwMDAwMCBuIAowMDAwMDMwNDMwIDAwMDAwIG4gCjAwMDAwMzEzMDIg
MDAwMDAgbiAKMDAwMDAwNTk3OCAwMDAwMCBuIAowMDAwMDI1NjY3IDAwMDAwIG4gCjAwMDAwMjk0
NzIgMDAwMDAgbiAKMDAwMDAyNTU1OSAwMDAwMCBuIAowMDAwMDI5MzYxIDAwMDAwIG4gCjAwMDAw
MjU0NDQgMDAwMDAgbiAKMDAwMDAyOTI1MCAwMDAwMCBuIAowMDAwMDI5ODk1IDAwMDAwIG4gCjAw
MDAwMjk2OTQgMDAwMDAgbiAKMDAwMDAzMDMyMSAwMDAwMCBuIAowMDAwMDI1MzI5IDAwMDAwIG4g
CjAwMDAwMjkxMzkgMDAwMDAgbiAKMDAwMDAyNTIxNCAwMDAwMCBuIAowMDAwMDI5MDI4IDAwMDAw
IG4gCjAwMDAwMjUwOTkgMDAwMDAgbiAKMDAwMDAyODkxNyAwMDAwMCBuIAowMDAwMDI0OTg0IDAw
MDAwIG4gCjAwMDAwMjg4MDYgMDAwMDAgbiAKMDAwMDAyNDg2OSAwMDAwMCBuIAowMDAwMDI4Njk1
IDAwMDAwIG4gCjAwMDAwMjQ3NTQgMDAwMDAgbiAKMDAwMDAyODU4NCAwMDAwMCBuIAowMDAwMDI0
NjM5IDAwMDAwIG4gCjAwMDAwMjg0NzMgMDAwMDAgbiAKMDAwMDAyNDUyNCAwMDAwMCBuIAowMDAw
MDI4MzYyIDAwMDAwIG4gCjAwMDAwMjQ0MDkgMDAwMDAgbiAKMDAwMDAyODI1MSAwMDAwMCBuIAow
MDAwMDI0Mjk0IDAwMDAwIG4gCjAwMDAwMjgxNDAgMDAwMDAgbiAKMDAwMDAyNDE3OSAwMDAwMCBu
IAowMDAwMDI4MDI5IDAwMDAwIG4gCjAwMDAwMjQwNjQgMDAwMDAgbiAKMDAwMDAyNzkxOCAwMDAw
MCBuIAowMDAwMDIzOTQ5IDAwMDAwIG4gCjAwMDAwMjc4MDcgMDAwMDAgbiAKMDAwMDAyMzgzNCAw
MDAwMCBuIAowMDAwMDI3Njk2IDAwMDAwIG4gCjAwMDAwMjM3MTkgMDAwMDAgbiAKMDAwMDAyNzU4
NSAwMDAwMCBuIAowMDAwMDIzNjA0IDAwMDAwIG4gCjAwMDAwMjc0NzQgMDAwMDAgbiAKMDAwMDAy
MzQ4OSAwMDAwMCBuIAowMDAwMDI3MzYzIDAwMDAwIG4gCjAwMDAwMjMzNzQgMDAwMDAgbiAKMDAw
MDAyNzI1MiAwMDAwMCBuIAowMDAwMDIzMjU5IDAwMDAwIG4gCjAwMDAwMjcxNDEgMDAwMDAgbiAK
MDAwMDAyMzE0NCAwMDAwMCBuIAowMDAwMDI3MDMwIDAwMDAwIG4gCjAwMDAwMjMwMjkgMDAwMDAg
biAKMDAwMDAyNjkxOSAwMDAwMCBuIAowMDAwMDIyOTE0IDAwMDAwIG4gCjAwMDAwMjY4MDggMDAw
MDAgbiAKMDAwMDAyMjc5OSAwMDAwMCBuIAowMDAwMDI2Njk3IDAwMDAwIG4gCjAwMDAwMjI2ODQg
MDAwMDAgbiAKMDAwMDAyNjU4NiAwMDAwMCBuIAowMDAwMDIyNTY5IDAwMDAwIG4gCjAwMDAwMjY0
NzUgMDAwMDAgbiAKMDAwMDAyMjQ1NCAwMDAwMCBuIAowMDAwMDI2MzY0IDAwMDAwIG4gCjAwMDAw
MjIzMzkgMDAwMDAgbiAKMDAwMDAyNjI1MyAwMDAwMCBuIAowMDAwMDIxOTA2IDAwMDAwIG4gCjAw
MDAwMjE5MzYgMDAwMDAgbiAKMDAwMDAyMTk3NyAwMDAwMCBuIAowMDAwMDI1ODkxIDAwMDAwIG4g
CjAwMDAwMzE0MTEgMDAwMDAgbiAKdHJhaWxlcgo8PCAvU2l6ZSA4NCAvUm9vdCAxIDAgUiAvSW5m
byAyIDAgUgovSUQgWzxGQjg0MTMxMTBDRjI5MkEwMzZEQjNBQzFGQTE3N0RGMT48RkI4NDEzMTEw
Q0YyOTJBMDM2REIzQUMxRkExNzdERjE+XQo+PgpzdGFydHhyZWYKMzI5MzAKJSVFT0YK};

	system("base64 -d -i EMI_Logo_std.pdf.b64 > EMI_Logo_std.pdf");
	system("rm EMI_Logo_std.pdf.b64");

}

