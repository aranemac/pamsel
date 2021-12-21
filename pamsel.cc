// pamsel 'Parse ModSecurity Error-Log'
// V 1.4.1 (c) 2021, A. Raphael
// License: MIT
// Contact: idicnet.de/pamsel


const char VERSION[] = "1.4.1";
const char LEGAL[] = "(c) 2021, A. Raphael - (MIT license)";

#include <stdio.h>
#include <stdlib.h>
#include <cstring>

const char DEFLOG[] = "/var/log/apache2/error.log";
const char DEFAUDIT[] = "/var/log/apache2/modsec_audit.log";
const char DEFSEP = '\t';
const char VALIDOPTIONS[] = "simturdanDclfFyxAvhV";
enum longoptions { OPT_NONE, OPT_DEBUG, OPT_DEFAULT, OPT_FULLDATE, OPT_SKIPPED, OPT_SEPARATOR };

#define SBUF 1000
#define MBUF 10000
char buf[MBUF];
char token[MBUF];
char lastuid[MBUF];
char exclude[MBUF];

#define MFIELDS 20
char field[MFIELDS][SBUF];
enum { MS_SEV, MS_ID, MS_MSG, MS_TAG, MS_URI, MS_REF, MS_DATE, MS_NOTE, MS_UID, MS_NUM, MS_DATA, MS_BLOCK };

char options[SBUF];
char done[SBUF];
char auditid[SBUF];
char auditsections[SBUF];
char logfile[SBUF];
char auditlog[SBUF];
char sep;

const char ESC_RED[]   = "\033[0;31m";
const char ESC_GREY[]  = "\033[1;30m";
const char ESC_CYAN[]  = "\033[0;36m";
//const char ESC_BROWN[] = "\033[0;33m";
const char ESC_GREEN[] = "\033[0;32m";
const char ESC_BLUE[]  = "\033[1;34m";
const char ESC_RESET[] = "\033[0m";


char* strncpy2( char *dst, char *src, size_t n )  {  strncpy( dst, src, n );  dst[n-1] = 0;  return dst;  }

int  getline2( char *buf, int max, FILE* inf );
int  strncpyoflow( char *dst, char *src, size_t n );
int  gettoken( char *token, char *buf, const char *id );
int  parseauditarg( char *auditsections, char *arg );
void showauditinfo( FILE *auf,  char* uniqueid );
void showhelp( void );


int main (int argc, char* argv[])
{
   FILE *inf,*auf;
   int   l,n;
   char *p,*pe,*p2;
   int   verbose, compressed, listformat, debug, skipflags, auditid, showskippedonly, highscore, blocked, exception, fulldate;
   char  lastoption;

   if (argc-1 < 1)
   {
      printf("Usage: pamsel OPTIONS\n");
      printf("       pamsel --def [MOREOPTIONS]\n");
      printf("       pamsel --help\n");
      return 1;
   }

   sep = DEFSEP;
   lastoption = 0;
   *logfile = 0;
   strcpy( auditlog, DEFAUDIT );
   auditid = 0;
   *auditsections = 0;
   *exclude = 0;
   showskippedonly = 0;
   fulldate = 0;
   debug = 0;

   *options = 0;
   for ( int i=1; i<argc; i++ )
   {
        p = argv[i];
        if ( p[0] == '-' ) {
                if ( p[1] == '-' )
                {
                        if ( strcasecmp(p+2, "def"     ) == 0 )  strcat( options, "ndsimu" ); else
                        if ( strcasecmp(p+2, "help"    ) == 0 )  strcat( options, "h" ); else
                        if ( strcasecmp(p+2, "version" ) == 0 )  strcat( options, "V" ); else
                        //if ( strcasecmp(p+2, "audit"   ) == 0 )  strcat( options, "A" ); else
                        //if ( strcasecmp(p+2, "alog"    ) == 0 )  strcat( options, "F" ); else
                        if ( strcasecmp(p+2, "skipped" ) == 0 )  showskippedonly = 1; else
                        if ( strcasecmp(p+2, "fulldate") == 0 )  fulldate = 1; else
                        if ( strcasecmp(p+2, "sep"     ) == 0 )  lastoption = OPT_SEPARATOR; else
                        if ( strcasecmp(p+2, "debug"   ) == 0 )  lastoption = OPT_DEBUG; else
                        {  printf("Invalid option: %s\n", p);  return 1; }
                } else
                {
                        strcat( options, p+1 );
                        lastoption = p[1];
                }
        } else {
                switch ( lastoption )
                {
                        case 'f':   strcpy(logfile, p);  break;
                        case 'x':   strcpy(exclude, p);  break;
                        case 'A':   auditid = parseauditarg( auditsections, p );  break;
                        case 'F':   strcpy(auditlog, p);  break;
                        case OPT_DEBUG:     debug = atoi( p );  break;
                        case OPT_SEPARATOR: sep = p[0];  break;
                        case   0:   printf("Missing option before argument: %s\n", p);  return 1;
                        default :   printf("'-%c %s' makes no sense ;-)\n", lastoption, p);  return 1;
                }
                lastoption = 0;
        }

   }

   for ( int i=0; i<strlen(options); i++ )
        {  if ( ! strchr( VALIDOPTIONS, options[i] ) ) { printf("Invalid option: -%c\n", options[i]);  return 1; }  }

   if ( strchr( options, 'h' ) )  {  showhelp();  return 0;  }
   if ( strchr( options, 'V' ) )  {  printf("pamsel %s\n%s\n", VERSION, LEGAL );  return 0;  }

   listformat = ( strchr( options, 'l' ) ? 1 : 0 );
   compressed = ( strchr( options, 'c' ) ? 1 : 0 );


   if ( *logfile == 0 ) strcpy( logfile, "/dev/stdin" );

   if ( strchr( options, 'y' ) )  // use yesterdays logs. overwrites other logfile options
   {
        strcpy( logfile,  DEFLOG   );  strcat( logfile, ".1" );
        strcpy( auditlog, DEFAUDIT );  strcat( auditlog, ".1" );
   }

   if ( ! ( inf = fopen( logfile, "rt" ) ) )  {  printf("Can't open %s\n", logfile);  return 1;  }

   if ( auditid > 0 )
   {
        auf = fopen( auditlog, "rt" );
        if ( ! auf ) {
                printf( "Can't open audit file %s\n", auditlog );
                fclose( inf );
                return 1;
        }
   }

// Here we go...
   n = 0;
   *lastuid = 0;
   while ( ! feof( inf ) )
   {
        l = getline2( buf, MBUF, inf );
        if ( l == 0 ) continue;

        p = strstr( buf, " ModSecurity: " );
        if ( ! p ) continue;
        if ( ! strstr( p, " [" ) )  continue;

        // must be set inside loop:
        verbose = ( ( strchr( options, 'v' ) || showskippedonly ) ? 1 : 0 );
        exception = 0;

        enum { FLAG_PCRE=1, FLAG_MUTEX=2, FLAG_ALLOWED=4, FLAG_MATCH=8 };
        // We skip these in normal (non verbose) mode:
        skipflags = 0;
        // modsec digging too deep into regexp. (php/modsec limits too low or buggy modsec-regexp):
        if ( strstr( buf, "Execution error - PCRE limits exceeded" ) )  {  skipflags |= FLAG_PCRE;  }
        // result of the former:
        if ( strstr( buf, "global mutex: Invalid argument" ) )  {  skipflags |= FLAG_MUTEX;  }
        // Occurrs sometimes when too many multiple entries are trying to be added to the audit log simultaneously

        // user-defined whitelisting-rules without 'nolog' (Message depends on configuration):
        if ( strstr( buf, "ModSecurity: Access allowed" ) )   {  skipflags |= FLAG_ALLOWED;  }

        // this one can occur with high frequency on whitelistings without 'nolog' (unwanted) but also in OWASP-rules (wanted) - see below
        if ( strstr( buf, "ModSecurity: Warning. String match" ) )   {  skipflags |= FLAG_MATCH;  }

        highscore = ( strstr( buf, "Anomaly Score Exceeded" ) != NULL );
        // In 'DetectionOnly'-Mode this message yields only redundant information
        // It is only relevant when requests are blocked:
        blocked = ( strstr( buf, "Access denied" ) != NULL );
        if ( highscore  && ( compressed || ! blocked  ) )  {  continue; }  // skip these messages if not blocked or turned off by user


// Parsing Apache
        if ( ! ( p = strstr(buf, "] ") ) ) {  if (verbose) printf("missing ']'\n"); continue; }
        *p = 0;
        if ( ! fulldate )  {  pe = strchr( buf+1, '.' );  if ( pe ) *pe = 0;  }  // shorten date format
        strncpy2(field[MS_DATE], buf+1, SBUF);

        if ( ! ( p = strstr(p+1, "[client ") ) ) {  if (verbose) printf("missing '[client ]'\n"); continue; } else
        if ( ! ( p = strstr(p+1, "[client ") ) ) {  if (verbose) printf("missing '[client ]'\n"); continue; }

        if ( ! ( pe = strstr(p, "]") ) ) {  if (verbose) printf("missing ']'\n"); continue; }
        *pe = 0; strncpy2(field[MS_REF], p+8, SBUF);

// Parsing ModSec
        if ( strncmp( pe+2, "ModSecurity", 11) != 0 ) { if (verbose) printf("missing 'ModSecurity'\n"); continue; }
        if ( ! ( p = strstr( pe+2, " [") ) ) {  if (verbose) printf("missing '['\n"); continue; }
        *p = 0;
        // cut off whole regexp pattern (too long). user has to look it up in audit log wtih -A
        p2 = strstr( pe+2, "Warning. Pattern match" );  if ( p2 ) *(p2+22)=0;
        strncpy2(field[MS_NOTE], pe+15, SBUF-20);  if ( p2 ) strcat( field[MS_NOTE], " (see audit log)" );

        // missing information, propably due to truncated log (insuficcient buffer size in modsec?)
        if ( strncmp( p+1, "[file ", 6)!=0 && !(skipflags&FLAG_MUTEX) )  {  verbose = 1;  exception = 1;  }

        gettoken( field[MS_ID  ], p+1, "id" );
        gettoken( field[MS_MSG ], p+1, "msg" );
        gettoken( field[MS_DATA], p+1, "data" );
        gettoken( field[MS_SEV ], p+1, "severity" );
        if ( blocked ) strcpy( field[MS_SEV], "BLOCKED" );
        if ( strcmp( field[MS_SEV], "CRITICAL" ) == 0 ) strcpy( field[MS_SEV ], "SERIOUS" ); // only to have a wordlength<8 (for tab-mode) ;-)
        gettoken( field[MS_URI ], p+1, "uri" );
        gettoken( field[MS_UID ], p+1, "unique_id");
        // Only the tag starting with OWASP_CRS is extracted: (focussing on OWAPS-ruleset)
        p2 = strstr( p+1, " [tag \"OWASP_CRS/" );
        if ( p2 )  {  pe = strstr( p2, "\"] ");  if ( pe )  *pe = 0;  }
        strncpy2(field[MS_TAG], (char*)(p2 && pe ? p2+7 : "-" ), SBUF);


        // All lines with same modsec-id belong to the same request
        if ( strcmp( field[MS_UID], lastuid ) != 0 )  n++;


	if ( (skipflags & FLAG_MATCH) && atoi(field[MS_ID])>=100000 ) skipflags ^= FLAG_MATCH;
	// skip "Warning. String match" only in self defined rules. (Usually whitelisting rules without 'nolog')

        if ( strstr( exclude, field[MS_ID] ) ) continue;  // exclude whitelisted rules

        if ( showskippedonly && ! skipflags ) continue;  // print only skipped lines (inverse verbose)
        if ( ! verbose && skipflags > 0 ) continue;  // skip special lines in nonverbose mode

        int nextrequest = ( strcmp( field[MS_UID], lastuid ) != 0 );

        if ( auditid>0 && auditid==n && strcmp( field[MS_UID], lastuid )!=0 )  showauditinfo( auf, field[MS_UID] );
        if ( auditid <= 0 || auditid == n )
        {
            const char *ESC_RULE    = ( highscore ? ESC_GREY : ESC_CYAN );
            const char *ESC_NOTE    = ( exception ? ESC_GREY : ESC_GREEN );

            *done = 0;
            for (int i=0; i<strlen(options); i++)
            {
                char fsep = ( listformat ? '\n' : sep );

                if ( strchr( done, options[i] ) ) continue;  // prevent multiple output if option occurs more than once
                switch ( options[i] )
                {
                        case 's' : printf("%s%s%s%s%c",     (listformat?"sev:  ":""), (blocked?ESC_RED:""), field[MS_SEV ], ESC_RESET, fsep); break;
                        case 'n' : printf("%s%s%04i%s%c",   (listformat?"cnt:  ":""), (nextrequest?"":ESC_GREY), n,  ESC_RESET, fsep); break;
                        case 'i' : printf("%s%s%s%s%c",     (listformat?"id:   ":""), ESC_RULE, field[MS_ID  ], ESC_RESET, fsep); break;
                        case 'm' : printf("%s%s\"%s\"%s%c", (listformat?"msg:  ":""), ESC_RULE, field[MS_MSG ], ESC_RESET, fsep); break;
                        case 'D' : printf("%s%s\"%s\"%s%c", (listformat?"data: ":""), ESC_BLUE, field[MS_DATA], ESC_RESET, fsep); break;
                        case 't' : printf("%s%s%c", (listformat?"tag:  ":""), field[MS_TAG ], fsep); break;
                        case 'u' : printf("%s%s%c", (listformat?"uri:  ":""), field[MS_URI ], fsep); break;
                        case 'r' : printf("%s%s%c", (listformat?"ip:   ":""), field[MS_REF ], fsep); break;
                        case 'd' : printf("%s%s%c", (listformat?"date: ":""), field[MS_DATE], fsep); break;
                        case 'a' : printf("%s%s%c", (listformat?"uid:  ":""), field[MS_UID ], fsep); break;
                        default: break;
                }
                strncat(done, &options[i], 1); // Yes, it's C :-)
            }

            if ( listformat )   {  if ( verbose ) printf("msec: %s\n", field[MS_NOTE]);  }
            else                {  if ( verbose ) printf("%s%s%s", ESC_NOTE, field[MS_NOTE], ESC_RESET );  else printf("-");  }

            printf("\n");
        }

        strcpy( lastuid, field[MS_UID] );
   }

   fcloseall();
   return 0;
}


int strncpyoflow( char *dst, char *src, size_t n )
{
        strncpy( dst, src, n );
        if ( dst[n-1] != 0 ) {  dst[n-1] = 0;  dst[n-2] = '>';  return -1;  }
        else return strlen( dst );
}


int gettoken( char *token, char *buf, const char *id )
{
        int rc = 0;

        char wbuf[MBUF];
        char xid[SBUF] = "";
        char *p,*pe;
        const char redundant[] = "Matched Data:";

        strncpy2(wbuf, buf, MBUF);
        strcat(xid, "[");
        strcat(xid, id);
        strcat(xid, " \"");

        p = strstr( wbuf, xid );
        if ( p )
        {
                p += strlen( xid );
                if ( strncmp( p, redundant, strlen(redundant) ) == 0 )  p += strlen( redundant );

                while ( *p == ' ' )  p++;
                pe = strchr( p, '\"' );
                if ( pe )
                {
                        *pe = 0;
                        int MAXCHARS = 80;
                        strncpyoflow( token, p, MAXCHARS );
                        rc = strlen( token );
                }
        }
        else
        {
                strcpy( token, "-" );
        }

        return rc;
}


int getline2(char* buf, int max, FILE* inf)
{
        int l;

        *buf = 0;
        fgets( buf, max, inf );
        l = strlen(buf);
        if    ( l>0 && buf[l-1]=='\n' ) buf[--l] = 0;
        while ( l>0 && buf[l-1]==' '  ) buf[--l] = 0;

        return l;
}


int parseauditarg( char *auditsections, char *arg )
{
        char *p;

        p = strstr( arg, "-" ); if ( !p ) p = strstr( arg, "+" );
        if ( p ) {  strcpy( auditsections, p );  *p = 0;  }
        return atoi(arg);
}


int getsectiontitle( char *p,  char t )
{
   switch ( t )
   {
        case 'B': strcpy( p, "  request header" );      break;
        case 'C': strcpy( p, "  request body" );        break;
        case 'E': strcpy( p, "  response body" );       break;
        case 'F': strcpy( p, "  response header" );     break;
        case 'H': strcpy( p, "  audit log trailer" );   break;
        case 'I': strcpy( p, "  compact request body" );break;
        case 'J': strcpy( p, "  uploaded files info" ); break;
        case 'K': strcpy( p, "  matching rules" );      break;
        default: *p=0;
   }
   return strlen( p );
}

void showauditinfo( FILE *auf,  char* uniqueid )
{
        int  n,l;
        char buf[MBUF];
        char lbuf[MBUF];
        char secinfo[SBUF];
        int  on = 0;    // found specified event
        int  step = 0;  // next section
        int  print = 0; // print this section
        char section = 0;

        //printf( "records in %s:\n", auditlog );
        n = 0;
        while ( ! feof(auf) )
        {
                if ( n>0 ) strcpy( lbuf, buf );  // save last line
                n++;

                l = getline2( buf, MBUF, auf );

                // next section (header format "--########-#--")
                if ( on && l==14 && buf[0]=='-' && buf[1]=='-' && buf[10]=='-' &&  buf[12]=='-' && buf[13]=='-' )
                {
                        section = buf[11];
                        getsectiontitle( secinfo, section );
                        strcat( buf, secinfo );
                        step = 1;
                }

                // check if this section should be printed
                if ( on && step )
                {
                        //printf( "nextline:\n%s\n", buf );
                        if ( section == 'Z' ) break;    // Terminator (No, not Arnold)
                        switch ( auditsections[0] ) {
                                case '-': print = 1;  if ( strchr( auditsections+1, section ) != NULL ) print = 0;  break;  // exclude this
                                case '+': print = 0;  if ( strchr( auditsections+1, section ) != NULL ) print = 1;  break;  // include this
                                default : print = 1;
                        }
                }

                if ( ! on ) {
                        if ( strstr( buf, uniqueid ) )  // this is the event, we are looking for
                        {
                                on = 1;
                                print = 1;
                                printf( "\n%s%s%s%s\n%s\n\n", ESC_GREEN, lbuf, "  audit log header", ESC_RESET, buf );
                                continue;
                        }
                }

                if ( on && print )
                {
                        if ( step )     printf( "\n%s%s%s\n", ESC_GREEN, buf, ESC_RESET );
                        else            printf( "%s\n", buf );

                        if ( section == 'H' )
                        {
                                if ( strncmp( buf, "Message: ",       9 ) == 0
                                ||   strncmp( buf, "Apache-Error: ", 14 ) == 0 )
                                     printf( "\n" );
                        }
                }
                step = 0;
        }

}


void showhelp( void )
{
        printf("pamsel - scans modsecurity logfiles (apache error and modsec audit)\n");
        printf("Usage: pamsel OPTIONS\n");
        printf("\nField display options:\n");
        printf("  -d  date/time\n");
        printf("  -u  requested url\n");
        printf("  -i  rule id\n");
        printf("  -m  modsec message\n");
        printf("  -t  rule tag (only OWASP_CRS/ tags are extracted!)\n");
        printf("  -s  severity\n");
        printf("  -r  referrer IP\n");
        printf("  -D  objected data (cut to first 80 chars. use -A to get full info)\n");
        printf("  -n  consecutive number (for lookup in audit log)\n");
        printf("  -a  unique modsec-id\n");
        printf("  field output is ordered according to the occurrence of the above options\n");
        printf("  --def = -ndsimu\n");
        printf("  --sep SEPARATOR (default is tab)\n");
        printf("\nGeneral options:\n");
        printf("  -v              verbose\n");
        printf("  --skipped       show only skipped entries (inverse verbose)\n");
        printf("  --fulldate      show full date (default is cut at first dot)\n");
        printf("  -l              list format (default is csv)\n");
        printf("  -c              dont't show if blocked (anomaly score exceeded)\n");
        printf("  -x id1,id2,..   exclude rules from parsing\n");
        //printf("  -A --audit NUMBER[-ABCD..|+ABCD..]\n");
        printf("  -A NUMBER[-ABCD..|+ABCD..]\n");
        printf("                  list info from audit-log for given entry (number from -n)\n");
        printf("                  -ABCD.. exclude specified audit-sections (\"all, except\")\n");
        printf("                  +ABCD.. show only the specified audit-sections (\"only these\")\n");
        //printf("  -F --alog AUDITLOGFILE\n");
        printf("  -F AUDITLOGFILE default is /var/log/apache2/modsec_audit.log\n");
        printf("                  note: take care that the audit-logfile corresponds with your error-log\n");
        printf("  -f ERRORLOG     if not given, pamsel reads from stdin/pipe\n");
        printf("  -y              use yesterdays logs (error.log.1 and modsec_audit.log.1) (overwrites other logfile options)\n");
        printf("  -V --version    version info\n");
        printf("  -h --help       this\n");
        printf("\nSome examples:\n");
        printf("  sudo cat /var/log/apache2/error.log | sudo ./pamsel -dimubT\n");
        printf("      lists all requests and rejections (tab-separated, one per line) with date, rule-id, message and url\n");
        printf("  sudo cat /var/log/apache2/error.log | sudo ./pamsel -im | sort | uniq -c\n");
        printf("      how often a rule is triggered\n");
        printf("  sudo cat /var/log/apache2/error.log | sudo ./pamsel -dim -x 920350,930130\n");
        printf("      exclude rules from listing\n");
        printf("  sudo cat /var/log/apache2/error.log | sudo ./pamsel -nrmu\n");
        printf("      -n gives every request an unique number...\n");
        printf("      ...which can be used to show the related info in audit-log:\n");
        printf("  sudo cat /var/log/apache2/error.log | sudo ./pamsel -nrmu -A 136\n");
        printf("      show only audit-sections B and H, to reduce the amount of information:\n");
        printf("  sudo cat /var/log/apache2/error.log | sudo ./pamsel -nrmu -A 136+BH\n");
        printf("      '-': all, except,  '+': only these  (A is listed anyway)\n");
        printf("\n");
}

