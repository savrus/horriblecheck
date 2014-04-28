/**
 * HorribleCheck version -0.1 (minus 0.1)
 * Verify that you have downloaded an animu correctly without watching it!
 *
 * Copyleft: 2014, savrus
 *
 * Permission is hereby blablabla, just do what you want with this.
 * No warranty, no usefullness, no work, no support and a lot of risk.
 * Yes, you may end up being banned from AniDB. You have been warned.
 */
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <wordexp.h>
#include <sys/stat.h>
#include <termios.h>
#include "rhash.h"

int sstartswith(const char *s1, const char *s2) {
    return ! strncmp(s1, s2, strlen(s2));
}

//======================= Query cache ================================
//
// AniDB want us to store answers to old queries. Okay.
//
#define CACHE_FILENAME "~/.horriblecheck.cache"
#define CACHE_BUF_SIZE (2*2048)
struct anidb_cache {
    char buf[CACHE_BUF_SIZE];
    int bufsize;
    char *filename;
    FILE *fd;
};
int anidb_cache_open(struct anidb_cache *cache) {
    cache->bufsize = CACHE_BUF_SIZE;
    cache->filename = CACHE_FILENAME;
    wordexp_t wexp;
    if (wordexp(cache->filename, &wexp, 0) != 0 || wexp.we_wordc < 1) {
        printf("wordexp() failed to expand path \"%s\"", cache->filename);
        return -1;
    }
    cache->fd = fopen(wexp.we_wordv[0], "rw+");
    wordfree(&wexp);
    if (cache->fd == NULL) {
        perror("fopen");
        return -1;
    }
    return 0;
}
void anidb_cache_close(struct anidb_cache *cache) {
    fclose(cache->fd);
}
int anidb_cache_add_entry(struct anidb_cache *cache, const char *key, const char *value) {
    if (fseek(cache->fd, 0, SEEK_END) == -1) {
        perror("fseek");
        return -1;
    }
    if (fseek(cache->fd, -1, SEEK_CUR) != -1) {
        unsigned char c = fgetc(cache->fd);
        if (c != '\n') fprintf(cache->fd,"\n");
    }
    size_t r = fprintf(cache->fd, "%s %s\n", key, value);
    if (r != strlen(key) + strlen(value) + 2) {
        printf("Write to cache failed\n");
        return -1;
    }
    return 0;
}
int anidb_cache_find_entry(struct anidb_cache *cache, const char *key, char *vbuf, size_t vlen) {
    assert(strlen(key) < cache->bufsize);
    if (fseek(cache->fd, 0, SEEK_SET) == -1) {
        perror("fseek");
        return -1;
    }
    clearerr(cache->fd);
    while(feof(cache->fd) == 0) {
        char *s = fgets(cache->buf, cache->bufsize, cache->fd);
        if (s == NULL) {
            if (feof(cache->fd)) break;
            printf("fgets failed!\n");
            return -1;
        }
        if (sstartswith(cache->buf, key)) {
            strncpy(vbuf, cache->buf + strlen(key) + 1, vlen);
            if (vlen + strlen(key) + 1 < strlen(cache->buf)) {
                printf("Entry for key \"%s\" in the cache is larger than buffer! Truncated.", key);
                vbuf[vlen-1] = '\0';
            }
            return 1;
        }
        // get to the next line
        while(!feof(cache->fd) && cache->buf[strlen(cache->buf)-1] != '\n')
            fgets(cache->buf, cache->bufsize, cache->fd);
    }
    return 0;
}


//======================= AniDB connection stuff ================================

//
// AniDB bans client which send more than 1 packet per 4 seconds.
// For this sake we wait before sending a packet.
// Also wait for the first packet since the last application run
// might be right before the current one.
//
#define ANIDB_WAIT (5)
struct anidb_comm {
    int socket;
    time_t last;
    int debug;
};
int anidb_comm_init(struct anidb_comm *comm) {
    if ((comm->socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("cannot create socket");
        return -1;
    } 
    struct sockaddr_in sa = { AF_INET, htons(9000), {INADDR_ANY}} ;
    //FIXME gethostbyname()
    if(inet_aton("50.30.46.102", &sa.sin_addr)==0) {
        perror("inet_aton");
        return -1;
    }
    if(connect(comm->socket, (struct sockaddr*) &sa, sizeof(sa))==-1) {
        perror("connect");
        return -1;
    }
    comm->last = time(NULL);
    comm->debug = 0;
    return 0;
}
void anidb_comm_fini(struct anidb_comm *comm) {
    close(comm->socket);
}
int anidb_comm_sendrecv(struct anidb_comm *comm, char *s, size_t slen, char *r, size_t rlen) {
    time_t now = time(NULL);
    if (now - comm->last < ANIDB_WAIT) {
        unsigned w = ANIDB_WAIT - (now - comm->last) + 1;
        now = time(NULL);
        if (comm->debug) fprintf(stderr, "%s (wait for %u seconds)\n", ctime(&now), w);
        sleep(w);
    }

    now = time(NULL);
    if (comm->debug) { fprintf(stderr, "%s (send) %s\n", ctime(&now), s); }
    //FIXME send, recv return values
    send(comm->socket, s, slen,0);
    size_t received = recv(comm->socket, r, rlen-1, 0);
    comm->last = time(NULL);
    if (received == -1) {
        perror("recv");
        return -1;
    }
    if (received == 0) {
        printf("recv: received zero bytes\n");
        return -1;
    }
    r[received - (r[received-1] == '\n' ? 1:0)] = '\0';
    now = time(NULL);
    if (comm->debug) { fprintf(stderr, "%s (recv) %s\n", ctime(&now), r); }
    return 0;
}

//======================= AniDB session stuff ================================

#define ANIDB_BUF_SIZE (2048)

struct anidb_session {
    struct anidb_comm comm;
    char *session_key;
    char sbuf[ANIDB_BUF_SIZE], rbuf[ANIDB_BUF_SIZE];
    size_t slen, rlen;
    struct anidb_cache cache;
};
int anidb_session_init(struct anidb_session *session) {
    session->session_key = NULL;
    session->slen = ANIDB_BUF_SIZE;
    session->rlen = ANIDB_BUF_SIZE;
    if (anidb_cache_open(&session->cache) == -1) return -1;
    return anidb_comm_init(&session->comm);
}
void anidb_session_fini(struct anidb_session *session) {
    anidb_comm_fini(&session->comm);
    anidb_cache_close(&session->cache);
    if (session->session_key != NULL) { free(session->session_key); session->session_key = NULL; }
}

int anidb_session_auth(struct anidb_session *session, const char *user, const char *pass) {
    size_t len = snprintf(session->sbuf, session->slen, "AUTH user=%s&pass=%s&protover=3&client=horriblecheck&clientver=0", user, pass);
    if (len +1 > session->slen) {
        printf("Line is too large\n");
        return -1;
    }
    int r = anidb_comm_sendrecv(&session->comm, session->sbuf, len+1, session->rbuf, session->rlen);
    if (r == -1) return -1;

    if (sstartswith(session->rbuf, "200 ") || sstartswith(session->rbuf, "201 ")) {
        int i = 4;
        while(session->rbuf[i] != ' ' && i < session->rlen) i++;
        if (i == session->rlen) {
            printf("Auth failed (no session key found): %s\n", session->rbuf);
        }
        session->session_key = strndup(session->rbuf + 4, i - 4);
        return 0;
    }
    printf("Auth failed: %s\n", session->rbuf);
    return -1;
}
int anidb_session_logout(struct anidb_session *session) {
    size_t len = snprintf(session->sbuf, session->slen, "LOGOUT s=%s", session->session_key);
    if (len +1 > session->slen) {
        printf("Line is too large\n");
        return -1;
    }
    return anidb_comm_sendrecv(&session->comm, session->sbuf, len+1, session->rbuf, session->rlen);
}
int anidb_session_query(struct anidb_session *session) {
    size_t len = strlen(session->sbuf);
    size_t len1 = snprintf(session->sbuf + len, session->slen - len, "&s=%s", session->session_key);
    if (len1 + 1 > session->slen - len) {
         printf("Query string is too large\n");
         return -1;
    }
    int r = anidb_comm_sendrecv(&session->comm, session->sbuf, len+len1, session->rbuf, session->rlen);
    if (r == -1) return -1;
    if (sstartswith(session->rbuf, "505 ")||sstartswith(session->rbuf, "598 ")) {
        printf("Got answer \"%s\" for the query \"%s\", please check the program\n",session->rbuf, session->sbuf);
        return -1;
    }
    if (sstartswith(session->rbuf, "555 ")) {
        printf("Got answer \"%s\" for the query \"%s\", you won't be able to connect for about 30 min\n",session->rbuf, session->sbuf);
        return -1;
    }
    if (session->rbuf[0] == '6'
        && session->rbuf[1] == '0'
        && session->rbuf[2] >= '0' && session->rbuf[2] <= '4'
        && session->rbuf[3] >= ' ' ) {
        printf("Got answer \"%s\" for the query \"%s\", conection problems, handling not implemented\n",session->rbuf, session->sbuf);
        return -1;
    }
    if (session->rbuf[0] == '6'
        && session->rbuf[1] == '0'
        && (session->rbuf[2] == '1' || session->rbuf[2] == '2' || session->rbuf[2] == '6')
        && session->rbuf[3] >= ' ' ) {
        // If ever implemented, need to keep track of logins to avoid flood here
        printf("Got answer \"%s\" for the query \"%s\", have to relogin, but not implemented\n",session->rbuf, session->sbuf);
        return -1;
    }
    session->sbuf[len] = '\0';
    return 0;
}
int anidb_session_file(struct anidb_session *session, const char *ed2k, long long size) {
    size_t len = snprintf(session->sbuf, session->slen, "FILE size=%lld&ed2k=%s&fmask=7108&amask=C0808040", size, ed2k);
    if (len +1 > session->slen) {
        printf("Line is too large\n");
        return -1;
    }
    if (anidb_cache_find_entry(&session->cache, session->sbuf, session->rbuf, session->rlen) != 1) {
        int r = anidb_session_query(session);
        if (r == -1) return -1;
        size_t i;
        for (i = 0; i < strlen(session->rbuf); ++i)
            if (session->rbuf[i] == '\n') session->rbuf[i] = ' ';
        if (sstartswith(session->rbuf, "220 ")
            || sstartswith(session->rbuf, "322 ")
            || sstartswith(session->rbuf, "320 ")) {
            anidb_cache_add_entry(&session->cache, session->sbuf, session->rbuf);
        }
    }

    if (sstartswith(session->rbuf, "220 FILE")) return 1;
    if (sstartswith(session->rbuf, "322 MULTIPLE FILES FOUND")) return 1;
    if (sstartswith(session->rbuf, "320 NO SUCH FILE")) return 0;
    printf("Unknown reply \"%s\" for file query \"%s\"\n", session->rbuf, session->sbuf);
    return -1;
}

//======================== manage files ================================

struct fileinfo {
    char *filename;
    long long size;
    char ed2k[33];
    char crc32[9];
    int good;
};

int fill_fileinfo(struct fileinfo *fi, char *filename, rhash rctx) {
    struct stat st;
    stat(filename, &st);
    fi->size = st.st_size;
    fi->filename = filename;
    FILE *f = fopen(filename, "rb");
    if (f == NULL) return -1;
    rhash_file_update(rctx,f);
    rhash_final(rctx, NULL);
    rhash_print(fi->ed2k, rctx, RHASH_ED2K,0);
    rhash_print(fi->crc32, rctx, RHASH_CRC32,RHPR_UPPERCASE);
    rhash_reset(rctx);
    fclose(f);
    return 0;
}

//============================ Halp ====================================


void usage() {
    printf("Usage: horriblecheck [-u user] [-s file.sfv] file1 file2...\n");
    printf("Check if file1, file2,... exits in the AniDB database\n");
    printf("  -u user        User name to connect to AniDB\n");
    printf("  -s file.sfv    Create sfv file with crc hashes for file1, file2,...\n");
    exit(0);
}

//======================= Read password ================================

static void gp_echo_off(struct termios *gp)
{
    struct termios newgp;
    tcgetattr(fileno(stdin), gp);
    newgp = *gp;
    newgp.c_lflag &= ~ECHO;
    tcsetattr(fileno(stdin), TCSADRAIN, &newgp);
}
static void gp_echo_restore(struct termios *gp)
{
    tcsetattr(fileno(stdin), TCSADRAIN, gp);
}
char * gp_readline(char *buf, unsigned int size, int echooff)
{
    struct termios gp;
    if (echooff) gp_echo_off(&gp);
    buf[size - 1] = 0;
    buf = fgets(buf, size, stdin);
    if (echooff) {gp_echo_restore(&gp); printf("\n"); }
    if (buf && (size = strlen(buf)) > 0 && buf[size - 1] == '\n') {
        buf[size - 1] = 0;
        return buf;
    } else
        return NULL;

}

//======================= Main programm ================================


int main(int argc, char *argv[]) {
    char username_buf[256], password_buf[256];
    char *username = NULL;
    char *password = NULL;
    char *sfvfile = NULL;

    int argi;
    for (argi = 1; argi < argc && argv[argi][0] == '-'; ++argi) {
        if (!strcmp(argv[argi], "--")) {
            ++argi;
            break;
        }
        if (!strcmp(argv[argi], "-s") || !strcmp(argv[argi], "--sfv")) {
            if (argi == argc - 1) usage();
            sfvfile = argv[++argi];
            continue;
        }
        if (!strcmp(argv[argi], "-u") || !strcmp(argv[argi], "--user")) {
            if (argi == argc - 1) usage();
            username = argv[++argi];
            continue;
        }
    }
    if (argi >= argc) usage();
    if (username == NULL) {
        printf("User: ");
        fflush(stdout);
        username = gp_readline(username_buf, sizeof(username_buf), 0);
        if (username == NULL) {
            printf("Bad username\n");
            exit(1);
        }
    }
    printf("Password: ");
    fflush(stdout);
    password = gp_readline(password_buf, sizeof(password_buf), 1);
    if (password == NULL) {
        printf("Badd password\n");
        exit(1);
    }

    rhash_library_init();
    rhash rctx = rhash_init(RHASH_ED2K|RHASH_CRC32);
    if (rctx == NULL) {
        printf("Unable to create rhash context\n");
        exit(1);
    }

    int filesc = argc - argi;
    struct fileinfo *fi = calloc(filesc, sizeof(struct fileinfo));
    if (fi == NULL) {
        perror("calloc");
        exit(1);
    }
    
    printf("Timeout for each query is %d seconds. Be patient.\n", ANIDB_WAIT);

#if 1
    struct anidb_session session;
    if (anidb_session_init(&session) == -1) {
        printf("Unable to connect ot AniDB\n");
        exit(1);
    }
    if (anidb_session_auth(&session, username, password) == -1) {
        exit(1);
    }
#endif
    //
    // FIXME: should catch Ctrl-C and logout from AniDB in case of iterrupt.
    // Open connections cause ban for a while
    //
    printf("Warning! Logged into AniDB database. Please don't abort to avoid loosing this session\n");

    int filei;
    int goodc = 0;
    for (filei = 0; argi < argc; ++argi, ++filei) {
        int r;
        r = fill_fileinfo(&fi[filei], argv[argi], rctx);
        if (r == -1) {
            printf("%s ERR (unable to open file)\n", argv[argi]);
            continue;
        }

        #if 1
        r = anidb_session_file(&session, fi[filei].ed2k, fi[filei].size);
        if (r == 1) {
            fi[filei].good = 1;
            goodc++;
        }
        #endif
        printf("%s %s\n", argv[argi], r == 1 ? "OK" : "ERR");
    }
    if (goodc == filesc) printf("Everything OK\n");

    if (goodc == filesc && sfvfile) {
        int i;
        FILE *f = fopen(sfvfile, "w");
        if (f == NULL) {
            printf("Unable to open file \"%s\"\n", sfvfile);
            exit(1);
        } else {
            printf("Write %s\n", sfvfile);
            fprintf(f,"; Generated by horriblecheck v-0.1\n\n");
            for(i = 0; i < filesc; i++) fprintf(f, "; %lld %s\n", fi[i].size, fi[i].filename);
            for(i = 0; i < filesc; i++) fprintf(f, "%s %s\n", fi[i].filename, fi[i].crc32);
            fclose(f);
        }
    }

#if 1
    anidb_session_logout(&session);
    anidb_session_fini(&session);
#endif

    rhash_free(rctx);

    free(fi);

    return 0;
}
