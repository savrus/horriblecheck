/**
 * HorribleCheck version -0.2 (minus 0.2)
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
#include <linux/limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>
#include "rhash.h"

#define OFFLINE 0

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

//======================= AniDB File Info parser ================================

#define ANIDB_PACKET_SIZE (1400)

struct anidb_fileinfo {
    char buf[ANIDB_PACKET_SIZE];
    char fmask[5];
    char amask[4];
    uint32_t fid;
    uint32_t aid;
    uint32_t eid;
    uint32_t gid;
    uint16_t state;
    int state_ver;
    int state_crc;
    int state_cen;
    char *crc32;
    uint32_t totaleps;
    uint32_t maxepno;
    char *aname;
    char *epno;
    char *gsname;
};
#define ANIDB_FILE_STATE_CRCOK  (1)
#define ANIDB_FILE_STATE_CRCERR (2)
#define ANIDB_FILE_STATE_UNC    (1)
#define ANIDB_FILE_STATE_CEN    (2)

int anidb_fileinfo_parse(const char *str, const char *fmask_str, const char *amask_str, struct anidb_fileinfo *afinfo) {
    if (sstartswith(str, "220 FILE ")) str += strlen("220 FILE ");
    else if (sstartswith(str, "322 MULTIPLE FILES FOUND ")) str += strlen("322 MULTIPLE FILES FOUND ");
    else return -1;
    //FIXME only first file is supported for answer answer "322 MULTIPLE FILES FOUND".
    //also may be some problems with the last field.

    memset(afinfo, 0, sizeof(struct anidb_fileinfo));

    assert(strlen(str) < sizeof(afinfo->buf));
    strcpy(afinfo->buf, str);
    char *buf = afinfo->buf;

    int i;
    for (i = strlen(buf)-1; i >= 0 && isspace(buf[i]); --i) buf[i] = '\0';

    char *fmask = afinfo->fmask;
    char *amask = afinfo->amask;
    char mask[3] = {0,0,0};
    for (i = 0; i < strlen(fmask_str); i+= 2) {
        mask[0] = fmask_str[i];
        mask[1] = fmask_str[i+1];
        fmask[i/2] = strtol(mask, NULL, 16);
    }
    for (i = 0; i < strlen(amask_str); i+= 2) {
        mask[0] = amask_str[i];
        mask[1] = amask_str[i+1];
        amask[i/2] = strtol(mask, NULL, 16);
    }

    char *s, *saveptr;
    s = strtok_r(buf, "|", &saveptr);
    afinfo->fid = strtol(s, NULL, 10);
    if (fmask[0] & 0x80) { assert(0); /* unused */ }
    if (fmask[0] & 0x40) { s = strtok_r(NULL, "|", &saveptr); afinfo->aid = strtol(s, NULL, 10); /* int4 aid */ }
    if (fmask[0] & 0x20) { s = strtok_r(NULL, "|", &saveptr); afinfo->eid = strtol(s, NULL, 10); /* int4 eid */ }
    if (fmask[0] & 0x10) { s = strtok_r(NULL, "|", &saveptr); afinfo->gid = strtol(s, NULL, 10); /* int4 gid */ }
    if (fmask[0] & 0x08) { s = strtok_r(NULL, "|", &saveptr); /* int4 mylist id */ }
    if (fmask[0] & 0x04) { s = strtok_r(NULL, "|", &saveptr); /* list other episodes */ }
    if (fmask[0] & 0x02) { s = strtok_r(NULL, "|", &saveptr); /* int2 IsDeprecated */ }
    if (fmask[0] & 0x01) { s = strtok_r(NULL, "|", &saveptr); afinfo->state = strtol(s, NULL, 10); /* int2 state */ }

    if (fmask[1] & 0x80) { s = strtok_r(NULL, "|", &saveptr); /* int8 size */ }
    if (fmask[1] & 0x40) { s = strtok_r(NULL, "|", &saveptr); /* str ed2k */ }
    if (fmask[1] & 0x20) { s = strtok_r(NULL, "|", &saveptr); /* str md5 */ }
    if (fmask[1] & 0x10) { s = strtok_r(NULL, "|", &saveptr); /* str sha1 */ }
    if (fmask[1] & 0x08) { s = strtok_r(NULL, "|", &saveptr); afinfo->crc32 = s; /* str crc32 */ }
    if (fmask[1] & 0x04) { assert(0); /* unused */ }
    if (fmask[1] & 0x02) { s = strtok_r(NULL, "|", &saveptr); /* video colour depth */ }
    if (fmask[1] & 0x01) { assert(0); /* reserved */ }

    if (fmask[2] & 0x80) { s = strtok_r(NULL, "|", &saveptr); /* str quality */ }
    if (fmask[2] & 0x40) { s = strtok_r(NULL, "|", &saveptr); /* str source */ }
    if (fmask[2] & 0x20) { s = strtok_r(NULL, "|", &saveptr); /* str audio codec list */ }
    if (fmask[2] & 0x10) { s = strtok_r(NULL, "|", &saveptr); /* int4 audio bitrate list */ }
    if (fmask[2] & 0x08) { s = strtok_r(NULL, "|", &saveptr); /* str video codec */ }
    if (fmask[2] & 0x04) { s = strtok_r(NULL, "|", &saveptr); /* int4 video bitrate */ }
    if (fmask[2] & 0x02) { s = strtok_r(NULL, "|", &saveptr); /* str video resolution */ }
    if (fmask[2] & 0x01) { s = strtok_r(NULL, "|", &saveptr); /* str file type (extension) */ }

    if (fmask[3] & 0x80) { s = strtok_r(NULL, "|", &saveptr); /* str dub language */ }
    if (fmask[3] & 0x40) { s = strtok_r(NULL, "|", &saveptr); /* str sub language */ }
    if (fmask[3] & 0x20) { s = strtok_r(NULL, "|", &saveptr); /* int4 length in seconds */ }
    if (fmask[3] & 0x10) { s = strtok_r(NULL, "|", &saveptr); /* str description */ }
    if (fmask[3] & 0x08) { s = strtok_r(NULL, "|", &saveptr); /* nt4 aired date */ }
    if (fmask[3] & 0x04) { assert(0); /* unused */ }
    if (fmask[3] & 0x02) { assert(0); /* unused */ }
    if (fmask[3] & 0x01) { s = strtok_r(NULL, "|", &saveptr); /* str anidb file name */ }

    if (fmask[4] & 0x80) { s = strtok_r(NULL, "|", &saveptr); /* int4 mylist state */ }
    if (fmask[4] & 0x40) { s = strtok_r(NULL, "|", &saveptr); /* int4 mylist filestate */ }
    if (fmask[4] & 0x20) { s = strtok_r(NULL, "|", &saveptr); /* int4 mylist viewed */ }
    if (fmask[4] & 0x10) { s = strtok_r(NULL, "|", &saveptr); /* int4 mylist viewdate */ }
    if (fmask[4] & 0x08) { s = strtok_r(NULL, "|", &saveptr); /* str mylist storage */ }
    if (fmask[4] & 0x04) { s = strtok_r(NULL, "|", &saveptr); /* str mylist source */ }
    if (fmask[4] & 0x02) { s = strtok_r(NULL, "|", &saveptr); /* str mylist other */ }
    if (fmask[4] & 0x01) { assert(0); /* unused */ }

    if (amask[0] & 0x80) { s = strtok_r(NULL, "|", &saveptr); afinfo->totaleps = strtol(s, NULL, 10); /* int4 anime total episodes */ }
    if (amask[0] & 0x40) { s = strtok_r(NULL, "|", &saveptr); afinfo->maxepno = strtol(s, NULL, 10); /* int4 highest episode number */ }
    if (amask[0] & 0x20) { s = strtok_r(NULL, "|", &saveptr); /* str year */ }
    if (amask[0] & 0x10) { s = strtok_r(NULL, "|", &saveptr); /* str type */ }
    if (amask[0] & 0x08) { s = strtok_r(NULL, "|", &saveptr); /* str related aid list */ }
    if (amask[0] & 0x04) { s = strtok_r(NULL, "|", &saveptr); /* str related aid type */ }
    if (amask[0] & 0x02) { s = strtok_r(NULL, "|", &saveptr); /* str category list */ }
    if (amask[0] & 0x01) { assert(0);  /* reserved */ }

    if (amask[1] & 0x80) { s = strtok_r(NULL, "|", &saveptr); afinfo->aname = s; /* str romaji name */ }
    if (amask[1] & 0x40) { s = strtok_r(NULL, "|", &saveptr); /* str kanji name */ }
    if (amask[1] & 0x20) { s = strtok_r(NULL, "|", &saveptr); /* str english name */ }
    if (amask[1] & 0x10) { s = strtok_r(NULL, "|", &saveptr); /* str other name */ }
    if (amask[1] & 0x08) { s = strtok_r(NULL, "|", &saveptr); /* str short name list */ }
    if (amask[1] & 0x04) { s = strtok_r(NULL, "|", &saveptr); /* str synonym list */ }
    if (amask[1] & 0x02) { assert(0);  /* retired */ }
    if (amask[1] & 0x01) { assert(0);  /* retired */ }

    if (amask[2] & 0x80) { s = strtok_r(NULL, "|", &saveptr); afinfo->epno = s; /* str epno */ }
    if (amask[2] & 0x40) { s = strtok_r(NULL, "|", &saveptr); /* str ep name */ }
    if (amask[2] & 0x20) { s = strtok_r(NULL, "|", &saveptr); /* str ep romaji name */ }
    if (amask[2] & 0x10) { s = strtok_r(NULL, "|", &saveptr); /* str ep kanji name */ }
    if (amask[2] & 0x08) { s = strtok_r(NULL, "|", &saveptr); /* int4 episode rating */ }
    if (amask[2] & 0x04) { s = strtok_r(NULL, "|", &saveptr); /* int4 episode vote count */ }
    if (amask[2] & 0x02) { assert(0); /* unused */ }
    if (amask[2] & 0x01) { assert(0); /* unused */ }

    if (amask[3] & 0x80) { s = strtok_r(NULL, "|", &saveptr); /* str group name */ }
    if (amask[3] & 0x40) { s = strtok_r(NULL, "|", &saveptr); afinfo->gsname = s; /* str group short name */ }
    if (amask[3] & 0x20) { assert(0); /* unused */ }
    if (amask[3] & 0x10) { assert(0); /* unused */ }
    if (amask[3] & 0x08) { assert(0); /* unused */ }
    if (amask[3] & 0x04) { assert(0); /* unused */ }
    if (amask[3] & 0x02) { assert(0); /* unused */ }
    if (amask[3] & 0x01) { s = strtok_r(NULL, "|", &saveptr); /* int4 date aid record updated */ }

    if (afinfo->state != 0) {
        afinfo->state_ver = 1;
        if (afinfo->state & 0x01) afinfo->state_crc = ANIDB_FILE_STATE_CRCOK;
        if (afinfo->state & 0x02) afinfo->state_crc = ANIDB_FILE_STATE_CRCERR;
        if (afinfo->state & 0x04) afinfo->state_ver = 2;
        if (afinfo->state & 0x08) afinfo->state_ver = 3;
        if (afinfo->state & 0x10) afinfo->state_ver = 4;
        if (afinfo->state & 0x20) afinfo->state_ver = 5;
        if (afinfo->state & 0x40) afinfo->state_cen = ANIDB_FILE_STATE_UNC;
        if (afinfo->state & 0x80) afinfo->state_cen = ANIDB_FILE_STATE_CEN;
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
#if OFFLINE
    return 0;
#endif
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
    if (session->session_key == NULL) {
        printf("Trying to logout when Not signed in\n");
        return -1;
    }
    size_t len = snprintf(session->sbuf, session->slen, "LOGOUT s=%s", session->session_key);
    if (len +1 > session->slen) {
        printf("Line is too large\n");
        return -1;
    }
    int r = anidb_comm_sendrecv(&session->comm, session->sbuf, len+1, session->rbuf, session->rlen);
    if (r == -1) {
        printf("Logout failed\n");
    }
    free(session->session_key);
    session->session_key = NULL;
    return 0;
}
int anidb_session_query(struct anidb_session *session) {
    size_t len = strlen(session->sbuf);
    size_t len1 = snprintf(session->sbuf + len, session->slen - len, "&s=%s", session->session_key);
    if (len1 + 1 > session->slen - len) {
         printf("Query string is too large\n");
         return -1;
    }
    session->rbuf[0] = '\0';
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
int anidb_session_file(struct anidb_session *session, const char *ed2k, long long size, struct anidb_fileinfo *afinfo) {
    char *fmask = "7108";
    char *amask = "C0808040";
    size_t len = snprintf(session->sbuf, session->slen, "FILE size=%lld&ed2k=%s&fmask=%s&amask=%s", size, ed2k, fmask, amask);
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

    if (sstartswith(session->rbuf, "320 NO SUCH FILE")) return 0;
    if (!(sstartswith(session->rbuf, "220 FILE") && !sstartswith(session->rbuf, "322 MULTIPLE FILES FOUND"))) {
        printf("Unknown reply \"%s\" for file query \"%s\"\n", session->rbuf, session->sbuf);
        return -1;
    }

    if (anidb_fileinfo_parse(session->rbuf, fmask, amask, afinfo) == -1) {
        printf("Couldn't parse FILE reply \"%s\" for query \"%s\"\n", session->rbuf, session->sbuf);
        return -1;
    }

    return 1;
}

//======================== manage files ================================

struct fileinfo {
    char filename[PATH_MAX];
    long long size;
    char ed2k[33];
    char crc32[9];
    int good;
};

int fill_fileinfo(struct fileinfo *fi, const char *filename, rhash rctx) {
    struct stat st;
    stat(filename, &st);
    if (!S_ISREG(st.st_mode)) return -1;
    fi->size = st.st_size;
    if (strlen(filename) > sizeof(fi->filename) - 1) return -1;
    strcpy(fi->filename, filename);
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

//======================= Check files and directories ====================

long directory_nfiles(const char *dirname) {
    DIR *dp;
    struct dirent *de;
    long nfiles = 0;
    if ((dp = opendir(dirname)) != NULL) {
        while ((de = readdir(dp)) != NULL) if (de->d_type == DT_REG) ++nfiles;
        closedir(dp);
    } else {
        perror("opendir");
        return -1;
    }
    return nfiles;
}

int check_file(const char *filename, struct fileinfo *fi, struct anidb_fileinfo *afi, struct anidb_session *session, rhash rctx) {
    printf("%s", filename);
    fflush(stdout);
    int r;
    r = fill_fileinfo(fi, filename, rctx);
    if (r == -1) {
        printf(" ERR (unable to open file)\n");
        return r;
    }
    r = anidb_session_file(session, fi->ed2k, fi->size, afi);
    printf(" %s", r == 1 ? "OK" : "ERR");
    if (r == 1) {
        printf(" {[%s] %s - %s}", afi->gsname, afi->aname, afi->epno);
        if (afi->state_ver > 1 || afi->state_crc != ANIDB_FILE_STATE_CRCOK || afi->state_cen == ANIDB_FILE_STATE_CEN) {
            printf(" {");
            char *sep = "";
            if (afi->state_ver > 1) {
                printf("V%d", afi->state_ver);
                sep = " ";
            }
            if (afi->state_crc != ANIDB_FILE_STATE_CRCOK) {
                printf("%s%s", sep, afi->state_crc == ANIDB_FILE_STATE_CRCERR ? "CRCERR" : "CRCUNK");
                sep = " ";
            }
            if (afi->state_cen == ANIDB_FILE_STATE_UNC)
                printf("%sCENSORED", sep);
            printf("}");
        }
    }
    printf("\n");
    return r;
}

int write_sfv_file(struct fileinfo *fi, int filesc, const char *sfvfile) {
    int i;
    FILE *f = fopen(sfvfile, "w");
    if (f == NULL) {
        printf("Unable to open sfv file \"%s\"\n", sfvfile);
        return -1;
    } else {
        printf("Write %s\n", sfvfile);
        fprintf(f,"; Generated by horriblecheck v-0.2\n\n");
        for(i = 0; i < filesc; i++) fprintf(f, "; %lld %s\n", fi[i].size, fi[i].filename);
        for(i = 0; i < filesc; i++) fprintf(f, "%s %s\n", fi[i].filename, fi[i].crc32);
        fclose(f);
    }
    return 0;
}

int check_directory(const char *dirname, struct anidb_session *session, rhash rctx) {
    int gooddir = 0;
    int ret = 0;
    if (chdir(dirname) == -1) {
        perror("chdir");
        printf("Could not chdir to directory \"%s\"\n", dirname);
        return -1;
    }

    long filesc = directory_nfiles(".");
    if (filesc == 0) {
        printf("Warning: directory '%s' is empty\n", dirname);
        goto leave;
    }

    struct fileinfo *fi = calloc(filesc, sizeof(struct fileinfo));
    if (fi == NULL) {
        perror("calloc");
        ret = -1;
        goto leave;

    }
    struct anidb_fileinfo *afi = calloc(filesc, sizeof(struct anidb_fileinfo));
    if (afi == NULL) {
        perror("calloc");
        free(fi);
        ret = -1;
        goto leave;
    }

    unsigned char *episodes = NULL;
    DIR *dp;
    struct dirent *de;
    int filei = 0;
    int goodi = 0;
    int aid = 0;
    int gid = 0;
    int neps = 0;
    int einanime = 1;
    int eingroup = 1;
    int allgood = 1;
    int nocrc = 0;
    if ((dp = opendir(".")) != NULL) {
        while ((de = readdir(dp)) != NULL) {
            // FIXME need to sort files...
            if (de->d_type == DT_DIR && strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
                //FIXME need to traverse subdirectories too
                printf("Skipped subdirectory '%s'\n", de->d_name);
            }
            if (de->d_type != DT_REG) continue;
            int r = check_file(de->d_name, &fi[filei], &afi[filei], session, rctx);
            if (r == 1) {
                ++goodi;

                if (aid == 0) aid = afi[filei].aid;
                else if (aid != afi[filei].aid) {
                    //FIXME: there could be some OVA, etc
                    einanime = 0;
                    continue;
                }
                if (gid == 0) gid = afi[filei].gid;
                else if (gid != afi[filei].gid) {
                    eingroup = 0;
                }
                if (neps == 0) {
                    neps = afi[filei].maxepno;
                    episodes = calloc(neps+1, sizeof(unsigned char));
                    if (episodes == NULL) {
                        perror("calloc");
                        closedir(dp);
                        ret = -1;
                        goto leave_ep;
                    }
                }
                char *end;
                long int epno = strtol(afi[filei].epno,&end,10);
                if (*end != '\0') {
                    //printf("Episode number '%s' is not a number\n", afi[filei].epno);
                    //allgood = 0;
                } else if (epno > neps) {
                    //printf("Episode number '%s' is larger than maximum episode number %d (total episodes %d)\n", afi[filei].epno, afi[filei].maxepno, afi[filei].totaleps);
                    //allgood = 0;
                } else if (episodes[epno]) {
                    printf("Episode '%s' appears more than once\n", afi[filei].epno);
                    allgood = 0;
                } else {
                    episodes[epno] = 1;
                }
                if (afi[filei].state_crc == ANIDB_FILE_STATE_CRCERR) {
                    allgood = 0;
                }
                if (afi[filei].state_crc == 0) {
                    nocrc = 1;
                }
            }
            filei++;
        }
        closedir(dp);
        if (goodi == 0) goto leave_ep;

        gooddir = goodi == filesc;
        if (afi[0].totaleps == 0) { printf("Animu is not finished\n"); gooddir = 0; }
        if (!einanime) { printf("There are files from different animus\n"); gooddir = 0; }
        if (!eingroup) { printf("There are files from different groups\n"); allgood = 0; }
        int i;
        int nmiss = 0;
        for (i = 1; i < neps; ++i) if (!episodes[i]) ++nmiss;
        if (nmiss > 0) {
            printf("Episode%s", nmiss == 1 ? "" : "s");
            char *sep = "";
            for (i = 1; i < neps; ++i) {
                if (!episodes[i]) printf("%s %d", sep, i);
                sep = ",";
            }
            printf(" %s missing\n", nmiss == 1 ? "is" : "are");
            gooddir = 0;
        }
        if (gooddir && allgood && nocrc) {
            // FIXME write svf if there were files with unknown crc status.
            // Note, that we don't look for crc in a file name.
            // Maybe, this need to be fixed.
            // Some about filename too
            char name[ANIDB_PACKET_SIZE];
            int i = 0, j;
            if (i < sizeof(name)) name[i++] = '[';
            for(j = 0; i < sizeof(name) && afi[0].gsname[j] != '\0'; ++i, ++j) {
                name[i] = afi[0].gsname[j];
            }
            if (i < sizeof(name)-1) {
                name[i++] = ']';
                name[i++] = ' ';
            }
            for(j = 0; i < sizeof(name)-1 && afi[0].aname[j] != '\0'; ++i, ++j) {
                char c = afi[0].aname[j];
                if (c == ':') {
                    name[i++] = ' ';
                    name[i] = '-';
                } else if (c == '/' || c=='|' || c==';' || c=='<' || c=='>') {
                    name[i] = ' ';
                } else {
                    name[i] = afi[0].aname[j];
                }
            }
            if (i < sizeof(name)-5) {
                strcpy(&name[i], ".sfv");
                i += 4;
            }
            if (name[i] != '\0') {
                printf("Error: Buffer is too small to hold a name for sfv file.\n");
                return ret;
            }
            write_sfv_file(fi, filesc, name);
        }
    } else {
        perror("opendir");
        ret = -1;
    }

    if (episodes != NULL) free(episodes);

leave_ep:
    free(afi);
    free(fi);

leave:
    if (chdir("..") == -1) {
        perror("chdir");
        printf("Could not chdir to directory \"..\"\n");
        return -2;
    }

    if (gooddir) {
        if (allgood) printf("Everything OK\n");
        else {
            printf("There are minor problems, but directory is good enough\n");
            if (nocrc) printf("There are some files with unknown crc status - better look at them\n");
        }

        char name[ANIDB_PACKET_SIZE];
        int i = 0, j;
        for(j = 0; i < sizeof(name)-1 && afi[0].aname[j] != '\0'; ++i, ++j) {
            char c = afi[0].aname[j];
            if (c == ':') {
                name[i++] = ' ';
                name[i] = '-';
            } else if (c == '/' || c=='|' || c==';' || c=='<' || c=='>') {
                name[i] = ' ';
            } else {
                name[i] = afi[0].aname[j];
            }
        }
        if (i < sizeof(name)-1) {
            name[i++] = ' ';
            name[i++] = '=';
        }
        for(j = 0;i < sizeof(name) && afi[0].gsname[j] != '\0'; ++i, ++j) {
            name[i] = afi[0].gsname[j];
        }
        if (i < sizeof(name)-1) {
            name[i++] = '=';
            name[i] = '\0';
        }
        if (name[i] != '\0') {
            printf("Error: Buffer is too small to hold a new name.\n");
            return ret;
        }
        char *path = malloc((strlen(dirname) + strlen(name) + 2) * sizeof(char));
        if (path == NULL) {
            perror("malloc");
            return ret;
        }
        strcpy(path, dirname);
        for (i = strlen(path) - 1; i > 0 && path[i] == '/'; --i) path[i] = '\0';
        char *p = strrchr(path, '/');
        p = (p == NULL) ? path : p + 1;
        strcpy(p, name);

        printf("Rename directory '%s' to '%s'\n", dirname, path);
        if (rename(dirname, path) == -1) {
            perror("rename");
            printf("Unable to rename directory '%s'\n", dirname);
        }
        free(path);
    }

    return ret;
}

int check_directory_list(int argc, char *argv[], struct anidb_session *session, rhash rctx) {
    int diri;
    for (diri = 0; diri < argc; ++diri) {
        #if 0
        wordexp_t wexp;
        int r;
        if ((r = wordexp(argv[diri], &wexp, 0)) != 0 || wexp.we_wordc < 1) {
            printf("wordexp() failed to expand path \"%s\", ret %d", argv[diri], r);
            return -1;
        }
        if (check_directory(wexp.we_wordv[0], session, rctx) <= -2) {
        #endif
        if (check_directory(argv[diri], session, rctx) <= -2) {
            printf("Grave error while processing directories. Aborting.\n");
            return -1;
        }
    }
    return 0;
}

int check_file_list(int argc, char *argv[], struct anidb_session *session, rhash rctx, char *sfvfile) {
    int ret = 0;
    int filesc = argc;
    struct fileinfo *fi = calloc(filesc, sizeof(struct fileinfo));
    if (fi == NULL) {
        perror("calloc");
        return -1;
    }
    struct anidb_fileinfo *afi = calloc(filesc, sizeof(struct anidb_fileinfo));
    if (afi == NULL) {
        perror("calloc");
        free(fi);
        return -1;
    }

    int filei;
    int goodc = 0;
    for (filei = 0; filei < argc; ++filei) {
        int r = check_file(argv[filei], &fi[filei], &afi[filei], session, rctx);
        if (r == 1) {
            goodc++;
        }
    }
    if (goodc == filesc) printf("Everything OK\n");

    if (goodc == filesc && sfvfile) {
        ret = write_sfv_file(fi, filesc, sfvfile);
    }

    free(afi);
    free(fi);

    return ret;
}

//======================= Handle interrupts ========================

struct anidb_session *g_session;

void ctrlc_handler(int signo, siginfo_t *sinfo, void *context) {
    //if (signo != SIGINT) {
        psignal(signo, "\nCaught signal");
    //}
    if (g_session->session_key) {
        //printf("Logout from AniDB\n");
        anidb_session_logout(g_session);
    }
    exit(0);
}

int set_ctrlc_handler() {
    struct sigaction sa = {.sa_sigaction = ctrlc_handler, .sa_flags = SA_SIGINFO };
    if (sigfillset(&sa.sa_mask) == -1) {
        printf("Warning: unable to fill signal mask");
    }
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        printf("Could not set Ctrl-C handler");
    }
    return 0;
}



//============================= main() =============================

int main(int argc, char *argv[]) {
    char username_buf[256], password_buf[256];
    char *username = NULL;
    char *password = NULL;
    char *sfvfile = NULL;
    int directory_mod = 0;

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
        if (!strcmp(argv[argi], "-d") || !strcmp(argv[argi], "--dir")) {
            directory_mod = 1;
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

    printf("Timeout for each query is %d seconds. Be patient.\n", ANIDB_WAIT);

    struct anidb_session session;
    g_session = &session;
    
    set_ctrlc_handler();

    if (anidb_session_init(&session) == -1) {
        printf("Unable to connect ot AniDB\n");
        exit(1);
    }
#if !OFFLINE
    if (anidb_session_auth(&session, username, password) == -1) {
        exit(1);
    }
#endif

    if (directory_mod) {
        check_directory_list(argc-argi, argv+argi, &session, rctx);
    } else {
        check_file_list(argc-argi, argv+argi, &session, rctx, sfvfile);
    }

#if !OFFLINE
    anidb_session_logout(&session);
#endif
    anidb_session_fini(&session);

    rhash_free(rctx);

    return 0;
}
