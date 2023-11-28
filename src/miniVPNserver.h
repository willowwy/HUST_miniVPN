#include <arpa/inet.h>
#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <math.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* define CERT_FILE_PATH to be dir for key and cert files... */
#define HOME "./cert_server/"

/* Make these what you want for cert & key files */
#define CERT_FILE_PATH HOME "server-wwy-crt.pem"
#define KEY_FILE_PATH HOME "server-wwy-key.pem"
#define CA_CERT_FILE_PATH HOME "ca-wwy-crt.pem"

#define LISTEN_PORT 4433
#define BUFF_SIZE 5000

#define CHK_NULL(x)  \
    if ((x) == NULL) \
    exit(1)
    
#define CHK_ERR(err, s) \
    if ((err) == -1) {  \
        perror(s);      \
        exit(1);        \
    }
#define CHK_SSL(err)                 \
    if ((err) == -1) {               \
        ERR_print_errors_fp(stderr); \
        exit(2);                     \
    }

typedef struct _mutexWorker {
    int num;
    pthread_mutex_t mutex;
    pthread_mutexattr_t mutexattr;
} mutexWorker;

typedef struct _pipeFileNode {
    char name[256];
    int pipefd;
    struct _pipeFileNode* next;
} pipeFileNode;

typedef struct _pipefdTable {
    int ipCode;
    char* object;
    int value;
    int len;
    struct _pipefdTable* next;
} pipefdTable;

typedef struct _pipeWorker {
    char pipe[512];
    SSL* ssl;
} pipeWorker;

typedef struct ipFlag {
    int area[256];
} ipFlag;

typedef struct _tunListenWork {
    int tunfd;
    int pipefdTableShareMemoryId;
    pipefdTable* tables;
} tunListenWorker;

int pipefdTable_ipCode(char* object, int len)
{
    int numOfDot = 0;
    int p;
    for (int i = 0; i < len; i++) {
        if (object[i] == '.') {
            numOfDot++;
        }
        if (numOfDot == 3) {
            p = i;
            break;
        }
    }
    p++;
    int ip = atoi(object + p);
    return ip;
}

void pipefdTable_insert(pipefdTable* tables, char* object, int len, int value)
{
    int ip = pipefdTable_ipCode(object, len);
    pipefdTable* head = &tables[ip];
    head->value = value;
}

void pipefdTable_insert_by_index(pipefdTable* tables, int index ,int value){
    tables[index].value = value;
}



pipefdTable* pipefdTable_get_by_index(pipefdTable* tables, int index){
    return &tables[index];
}

pipefdTable* pipefdTable_get(pipefdTable* tables, char* object, int len)
{
    printf("Start pipefdTable_get\n");
    int ip = pipefdTable_ipCode(object, len);
    return &tables[ip];
}

void pipefdTable_delete(pipefdTable* tables, char* object, int len)
{
    if (object == NULL) {
        return;
    }
    int ip = pipefdTable_ipCode(object, len);
    pipefdTable* head = &tables[ip];
    head->value = 0;
}

void mutexWorkerInit(mutexWorker* worker)
{
    pthread_mutexattr_init(&worker->mutexattr); //初始化mutex属性对象
    pthread_mutexattr_setpshared(&worker->mutexattr, PTHREAD_PROCESS_SHARED); //修改属性为进程间共享
    pthread_mutex_init(&worker->mutex, &worker->mutexattr); //初始化一把mutex锁
}

SSL* sslInit()
{
    // Step 0: OpenSSL library initialization
    // This step is no longer needed as of version 1.1.0.
    SSL_METHOD* meth;
    SSL_CTX* ctx;
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    // Step 1: SSL context initialization
    meth = (SSL_METHOD*)SSLv23_server_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE_PATH, NULL);

    // Step 2: Set up the server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE_PATH, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(3);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE_PATH, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(4);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(5);
    }
    // Step 3: Create a new SSL structure for a connection
    return SSL_new(ctx);
}

int setupTCPServer()
{
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset(&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port = htons(LISTEN_PORT);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));

    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

#define LINKED_LIST
