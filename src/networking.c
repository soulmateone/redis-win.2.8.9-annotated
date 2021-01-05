/*
 * Copyright (c) 2009-2012, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "redis.h"
#ifndef _WIN32
#include <sys/uio.h>
#endif
#include <math.h>

static void setProtocolError(redisClient *c, int pos);

/* To evaluate the output buffer size of a client we need to get size of
 * allocated objects, however we can't used zmalloc_size() directly on sds
 * strings because of the trick they use to work (the header is before the
 * returned pointer), so we use this helper function. */
size_t zmalloc_size_sds(sds s) {
    return zmalloc_size(s-sizeof(struct sdshdr));
}

void *dupClientReplyValue(void *o) {
    incrRefCount((robj*)o);
    return o;
}

int listMatchObjects(void *a, void *b) {
    return equalStringObjects(a,b);
}

redisClient *createClient(int fd) {
    redisClient *c = zmalloc(sizeof(redisClient));

    /* passing -1 as fd it is possible to create a non connected client.
     * This is useful since all the Redis commands needs to be executed
     * in the context of a client. When commands are executed in other
     * contexts (for instance a Lua script) we need a non connected client. */
    if (fd != -1) {
        anetNonBlock(NULL,fd);
        anetEnableTcpNoDelay(NULL,fd);
        if (server.tcpkeepalive)
            anetKeepAlive(NULL,fd,server.tcpkeepalive);

		// 为客户端连接的套接字，注册读事件回调 readQueryFromClient
        if (aeCreateFileEvent(server.el,fd,AE_READABLE,
            readQueryFromClient, c) == AE_ERR)
        {
#ifdef WIN32_IOCP
            aeWinCloseSocket(fd);
#else
        close(fd);
#endif
            zfree(c);
            return NULL;
        }
    }

    selectDb(c,0);
    c->fd = fd;
    c->name = NULL;
    c->bufpos = 0;
    c->querybuf = sdsempty();
    c->querybuf_peak = 0;
    c->reqtype = 0;
    c->argc = 0;
    c->argv = NULL;
    c->cmd = c->lastcmd = NULL;
    c->multibulklen = 0;
    c->bulklen = -1;
    c->sentlen = 0;
    c->flags = 0;
    c->ctime = c->lastinteraction = server.unixtime;
    c->authenticated = 0;
    c->replstate = REDIS_REPL_NONE;
    c->reploff = 0;
    c->repl_ack_off = 0;
    c->repl_ack_time = 0;
    c->slave_listening_port = 0;
    c->reply = listCreate();
    c->reply_bytes = 0;
    c->obuf_soft_limit_reached_time = 0;
    listSetFreeMethod(c->reply,decrRefCountVoid);
    listSetDupMethod(c->reply,dupClientReplyValue);
    c->bpop.keys = dictCreate(&setDictType,NULL);
    c->bpop.timeout = 0;
    c->bpop.target = NULL;
    c->watched_keys = listCreate();
    c->pubsub_channels = dictCreate(&setDictType,NULL);
    c->pubsub_patterns = listCreate();
    listSetFreeMethod(c->pubsub_patterns,decrRefCountVoid);
    listSetMatchMethod(c->pubsub_patterns,listMatchObjects);
    if (fd != -1) listAddNodeTail(server.clients,c);
    initClientMultiState(c);
    return c;
}

/* This function is called every time we are going to transmit new data
 * to the client. The behavior is the following:
 *
 * If the client should receive new data (normal clients will) the function
 * returns REDIS_OK, and make sure to install the write handler in our event
 * loop so that when the socket is writable new data gets written.
 *
 * If the client should not receive new data, because it is a fake client,
 * a master, a slave not yet online, or because the setup of the write handler
 * failed, the function returns REDIS_ERR.
 *
 * Typically gets called every time a reply is built, before adding more
 * data to the clients output buffers. If the function returns REDIS_ERR no
 * data should be appended to the output buffers. */
int prepareClientToWrite(redisClient *c) {
    if (c->flags & REDIS_LUA_CLIENT) return REDIS_OK;
    if ((c->flags & REDIS_MASTER) &&
        !(c->flags & REDIS_MASTER_FORCE_REPLY)) return REDIS_ERR;
    if (c->fd <= 0) return REDIS_ERR; /* Fake client */
    if (c->bufpos == 0 && listLength(c->reply) == 0 &&
        (c->replstate == REDIS_REPL_NONE ||
         c->replstate == REDIS_REPL_ONLINE) &&
        aeCreateFileEvent(server.el, c->fd, AE_WRITABLE,
        sendReplyToClient, c) == AE_ERR) return REDIS_ERR;
    return REDIS_OK;
}

/* Create a duplicate of the last object in the reply list when
 * it is not exclusively owned by the reply list. */
robj *dupLastObjectIfNeeded(list *reply) {
    robj *new, *cur;
    listNode *ln;
    redisAssert(listLength(reply) > 0);
    ln = listLast(reply);
    cur = listNodeValue(ln);
    if (cur->refcount > 1) {
        new = dupStringObject(cur);
        decrRefCount(cur);
        listNodeValue(ln) = new;
    }
    return listNodeValue(ln);
}

/* -----------------------------------------------------------------------------
 * Low level functions to add more data to output buffers.
 * -------------------------------------------------------------------------- */

int _addReplyToBuffer(redisClient *c, char *s, size_t len) {
    size_t available = sizeof(c->buf)-c->bufpos;

    if (c->flags & REDIS_CLOSE_AFTER_REPLY) return REDIS_OK;

    /* If there already are entries in the reply list, we cannot
     * add anything more to the static buffer. */
    if (listLength(c->reply) > 0) return REDIS_ERR;

    /* Check that the buffer has enough space available for this string. */
    if (len > available) return REDIS_ERR;

    memcpy(c->buf+c->bufpos,s,len);
    c->bufpos+=(int)len;
    return REDIS_OK;
}

void _addReplyObjectToList(redisClient *c, robj *o) {
    robj *tail;

    if (c->flags & REDIS_CLOSE_AFTER_REPLY) return;

    if (listLength(c->reply) == 0) {
        incrRefCount(o);
        listAddNodeTail(c->reply,o);
        c->reply_bytes += (unsigned long)zmalloc_size_sds(o->ptr);
    } else {
        tail = listNodeValue(listLast(c->reply));

        /* Append to this object when possible. */
        if (tail->ptr != NULL &&
            sdslen(tail->ptr)+sdslen(o->ptr) <= REDIS_REPLY_CHUNK_BYTES)
        {
            c->reply_bytes -= (unsigned long)zmalloc_size_sds(tail->ptr);
            tail = dupLastObjectIfNeeded(c->reply);
            tail->ptr = sdscatlen(tail->ptr,o->ptr,sdslen(o->ptr));
            c->reply_bytes += (unsigned long)zmalloc_size_sds(tail->ptr);
        } else {
            incrRefCount(o);
            listAddNodeTail(c->reply,o);
            c->reply_bytes += (unsigned long)zmalloc_size_sds(o->ptr);
        }
    }
    asyncCloseClientOnOutputBufferLimitReached(c);
}

/* This method takes responsibility over the sds. When it is no longer
 * needed it will be free'd, otherwise it ends up in a robj. */
void _addReplySdsToList(redisClient *c, sds s) {
    robj *tail;

    if (c->flags & REDIS_CLOSE_AFTER_REPLY) {
        sdsfree(s);
        return;
    }

    if (listLength(c->reply) == 0) {
        listAddNodeTail(c->reply,createObject(REDIS_STRING,s));
        c->reply_bytes += (unsigned long)zmalloc_size_sds(s);
    } else {
        tail = listNodeValue(listLast(c->reply));

        /* Append to this object when possible. */
        if (tail->ptr != NULL &&
            sdslen(tail->ptr)+sdslen(s) <= REDIS_REPLY_CHUNK_BYTES)
        {
            c->reply_bytes -= (unsigned long)zmalloc_size_sds(tail->ptr);
            tail = dupLastObjectIfNeeded(c->reply);
            tail->ptr = sdscatlen(tail->ptr,s,sdslen(s));
            c->reply_bytes += (unsigned long)zmalloc_size_sds(tail->ptr);
            sdsfree(s);
        } else {
            listAddNodeTail(c->reply,createObject(REDIS_STRING,s));
            c->reply_bytes += (unsigned long)zmalloc_size_sds(s);
        }
    }
    asyncCloseClientOnOutputBufferLimitReached(c);
}

void _addReplyStringToList(redisClient *c, char *s, size_t len) {
    robj *tail;

    if (c->flags & REDIS_CLOSE_AFTER_REPLY) return;

    if (listLength(c->reply) == 0) {
        robj *o = createStringObject(s,len);

        listAddNodeTail(c->reply,o);
        c->reply_bytes += (unsigned long)zmalloc_size_sds(o->ptr);
    } else {
        tail = listNodeValue(listLast(c->reply));

        /* Append to this object when possible. */
        if (tail->ptr != NULL &&
            sdslen(tail->ptr)+len <= REDIS_REPLY_CHUNK_BYTES)
        {
            c->reply_bytes -= (unsigned long)zmalloc_size_sds(tail->ptr);
            tail = dupLastObjectIfNeeded(c->reply);
            tail->ptr = sdscatlen(tail->ptr,s,len);
            c->reply_bytes += (unsigned long)zmalloc_size_sds(tail->ptr);
        } else {
            robj *o = createStringObject(s,len);

            listAddNodeTail(c->reply,o);
            c->reply_bytes += (unsigned long)zmalloc_size_sds(o->ptr);
        }
    }
    asyncCloseClientOnOutputBufferLimitReached(c);
}

/* -----------------------------------------------------------------------------
 * Higher level functions to queue data on the client output buffer.
 * The following functions are the ones that commands implementations will call.
 * -------------------------------------------------------------------------- */

void addReply(redisClient *c, robj *obj) {
    if (prepareClientToWrite(c) != REDIS_OK) return;

    /* This is an important place where we can avoid copy-on-write
     * when there is a saving child running, avoiding touching the
     * refcount field of the object if it's not needed.
     *
     * If the encoding is RAW and there is room in the static buffer
     * we'll be able to send the object to the client without
     * messing with its page. */
    if (obj->encoding == REDIS_ENCODING_RAW) {
        if (_addReplyToBuffer(c,obj->ptr,sdslen(obj->ptr)) != REDIS_OK)
            _addReplyObjectToList(c,obj);
    } else if (obj->encoding == REDIS_ENCODING_INT) {
        /* Optimization: if there is room in the static buffer for 32 bytes
         * (more than the max chars a 64 bit integer can take as string) we
         * avoid decoding the object and go for the lower level approach. */
        if (listLength(c->reply) == 0 && (sizeof(c->buf) - c->bufpos) >= 32) {
            char buf[32];
            int len;

            len = ll2string(buf,sizeof(buf),(long)obj->ptr);
            if (_addReplyToBuffer(c,buf,len) == REDIS_OK)
                return;
            /* else... continue with the normal code path, but should never
             * happen actually since we verified there is room. */
        }
        obj = getDecodedObject(obj);
        if (_addReplyToBuffer(c,obj->ptr,sdslen(obj->ptr)) != REDIS_OK)
            _addReplyObjectToList(c,obj);
        decrRefCount(obj);
    } else {
        redisPanic("Wrong obj->encoding in addReply()");
    }
}

void addReplySds(redisClient *c, sds s) {
    if (prepareClientToWrite(c) != REDIS_OK) {
        /* The caller expects the sds to be free'd. */
        sdsfree(s);
        return;
    }
    if (_addReplyToBuffer(c,s,sdslen(s)) == REDIS_OK) {
        sdsfree(s);
    } else {
        /* This method free's the sds when it is no longer needed. */
        _addReplySdsToList(c,s);
    }
}

void addReplyString(redisClient *c, char *s, size_t len) {
    if (prepareClientToWrite(c) != REDIS_OK) return;
    if (_addReplyToBuffer(c,s,len) != REDIS_OK)
        _addReplyStringToList(c,s,len);
}

void addReplyErrorLength(redisClient *c, char *s, size_t len) {
    addReplyString(c,"-ERR ",5);
    addReplyString(c,s,len);
    addReplyString(c,"\r\n",2);
}

void addReplyError(redisClient *c, char *err) {
    addReplyErrorLength(c,err,strlen(err));
}

void addReplyErrorFormat(redisClient *c, const char *fmt, ...) {
    size_t l, j;
    va_list ap;
    sds s;
    va_start(ap,fmt);
    s = sdscatvprintf(sdsempty(),fmt,ap);
    va_end(ap);
    /* Make sure there are no newlines in the string, otherwise invalid protocol
     * is emitted. */
    l = sdslen(s);
    for (j = 0; j < l; j++) {
        if (s[j] == '\r' || s[j] == '\n') s[j] = ' ';
    }
    addReplyErrorLength(c,s,sdslen(s));
    sdsfree(s);
}

void addReplyStatusLength(redisClient *c, char *s, size_t len) {
    addReplyString(c,"+",1);
    addReplyString(c,s,len);
    addReplyString(c,"\r\n",2);
}

void addReplyStatus(redisClient *c, char *status) {
    addReplyStatusLength(c,status,strlen(status));
}

void addReplyStatusFormat(redisClient *c, const char *fmt, ...) {
    sds s;
    va_list ap;
    va_start(ap,fmt);
    s = sdscatvprintf(sdsempty(),fmt,ap);
    va_end(ap);
    addReplyStatusLength(c,s,sdslen(s));
    sdsfree(s);
}

/* Adds an empty object to the reply list that will contain the multi bulk
 * length, which is not known when this function is called. */
void *addDeferredMultiBulkLength(redisClient *c) {
    /* Note that we install the write event here even if the object is not
     * ready to be sent, since we are sure that before returning to the
     * event loop setDeferredMultiBulkLength() will be called. */
    if (prepareClientToWrite(c) != REDIS_OK) return NULL;
    listAddNodeTail(c->reply,createObject(REDIS_STRING,NULL));
    return listLast(c->reply);
}

/* Populate the length object and try gluing it to the next chunk. */
void setDeferredMultiBulkLength(redisClient *c, void *node, long length) {
    listNode *ln = (listNode*)node;
    robj *len, *next;

    /* Abort when *node is NULL (see addDeferredMultiBulkLength). */
    if (node == NULL) return;

    len = listNodeValue(ln);
    len->ptr = sdscatprintf(sdsempty(),"*%ld\r\n",length);
    c->reply_bytes += (unsigned long)zmalloc_size_sds(len->ptr);
    if (ln->next != NULL) {
        next = listNodeValue(ln->next);

        /* Only glue when the next node is non-NULL (an sds in this case) */
        if (next->ptr != NULL) {
            c->reply_bytes -= (unsigned long)zmalloc_size_sds(len->ptr);
            c->reply_bytes -= (unsigned long)zmalloc_size_sds(next->ptr);
            len->ptr = sdscatlen(len->ptr,next->ptr,sdslen(next->ptr));
            c->reply_bytes += (unsigned long)zmalloc_size_sds(len->ptr);
            listDelNode(c->reply,ln->next);
        }
    }
    asyncCloseClientOnOutputBufferLimitReached(c);
}

/* Add a double as a bulk reply */
void addReplyDouble(redisClient *c, double d) {
    char dbuf[128], sbuf[128];
    int dlen, slen;
    if (isinf(d)) {
        /* Libc in odd systems (Hi Solaris!) will format infinite in a
         * different way, so better to handle it in an explicit way. */
        addReplyBulkCString(c, d > 0 ? "inf" : "-inf");
    } else {
        dlen = snprintf(dbuf,sizeof(dbuf),"%.17g",d);
        slen = snprintf(sbuf,sizeof(sbuf),"$%d\r\n%s\r\n",dlen,dbuf);
        addReplyString(c,sbuf,slen);
    }
}

/* Add a long long as integer reply or bulk len / multi bulk count.
 * Basically this is used to output <prefix><long long><crlf>. */
void addReplyLongLongWithPrefix(redisClient *c, long long ll, char prefix) {
    char buf[128];
    int len;

    /* Things like $3\r\n or *2\r\n are emitted very often by the protocol
     * so we have a few shared objects to use if the integer is small
     * like it is most of the times. */
    if (prefix == '*' && ll < REDIS_SHARED_BULKHDR_LEN) {
        addReply(c,shared.mbulkhdr[ll]);
        return;
    } else if (prefix == '$' && ll < REDIS_SHARED_BULKHDR_LEN) {
        addReply(c,shared.bulkhdr[ll]);
        return;
    }

    buf[0] = prefix;
    len = ll2string(buf+1,sizeof(buf)-1,ll);
    buf[len+1] = '\r';
    buf[len+2] = '\n';
    addReplyString(c,buf,len+3);
}

void addReplyLongLong(redisClient *c, long long ll) {
    if (ll == 0)
        addReply(c,shared.czero);
    else if (ll == 1)
        addReply(c,shared.cone);
    else
        addReplyLongLongWithPrefix(c,ll,':');
}

void addReplyMultiBulkLen(redisClient *c, long length) {
    if (length < REDIS_SHARED_BULKHDR_LEN)
        addReply(c,shared.mbulkhdr[length]);
    else
        addReplyLongLongWithPrefix(c,length,'*');
}

/* Create the length prefix of a bulk reply, example: $2234 */
void addReplyBulkLen(redisClient *c, robj *obj) {
    size_t len;

    if (obj->encoding == REDIS_ENCODING_RAW) {
        len = sdslen(obj->ptr);
    } else {
        long n = (long)obj->ptr;

        /* Compute how many bytes will take this integer as a radix 10 string */
        len = 1;
        if (n < 0) {
            len++;
            n = -n;
        }
        while((n = n/10) != 0) {
            len++;
        }
    }

    if (len < REDIS_SHARED_BULKHDR_LEN)
        addReply(c,shared.bulkhdr[len]);
    else
        addReplyLongLongWithPrefix(c,len,'$');
}

/* Add a Redis Object as a bulk reply */
void addReplyBulk(redisClient *c, robj *obj) {
    addReplyBulkLen(c,obj);
    addReply(c,obj);
    addReply(c,shared.crlf);
}

/* Add a C buffer as bulk reply */
void addReplyBulkCBuffer(redisClient *c, void *p, size_t len) {
    addReplyLongLongWithPrefix(c,len,'$');
    addReplyString(c,p,len);
    addReply(c,shared.crlf);
}

/* Add a C nul term string as bulk reply */
void addReplyBulkCString(redisClient *c, char *s) {
    if (s == NULL) {
        addReply(c,shared.nullbulk);
    } else {
        addReplyBulkCBuffer(c,s,strlen(s));
    }
}

/* Add a long long as a bulk reply */
void addReplyBulkLongLong(redisClient *c, long long ll) {
    char buf[64];
    int len;

    len = ll2string(buf,64,ll);
    addReplyBulkCBuffer(c,buf,len);
}

/* Copy 'src' client output buffers into 'dst' client output buffers.
 * The function takes care of freeing the old output buffers of the
 * destination client. */
void copyClientOutputBuffer(redisClient *dst, redisClient *src) {
    listRelease(dst->reply);
    dst->reply = listDup(src->reply);
    memcpy(dst->buf,src->buf,src->bufpos);
    dst->bufpos = src->bufpos;
    dst->reply_bytes = src->reply_bytes;
}

static void acceptCommonHandler(int fd, int flags) {
    redisClient *c;
	// 对于每个客户端的连接请求，创建一个redisClient
    if ((c = createClient(fd)) == NULL) {
        redisLog(REDIS_WARNING,
            "Error registering fd event for the new client: %s (fd=%d)",
            strerror(errno),fd);
#ifdef WIN32_IOCP
        aeWinCloseSocket(fd); /* May be already closed, just ingore errors */
#else
        close(fd); /* May be already closed, just ingore errors */
#endif
        return;
    }
    /* If maxclient directive is set and this is one client more... close the
     * connection. Note that we create the client instead to check before
     * for this condition, since now the socket is already set in non-blocking
     * mode and we can send an error for free using the Kernel I/O */
    if (listLength(server.clients) > server.maxclients) {
        char *err = "-ERR max number of clients reached\r\n";

        /* That's a best effort error message, don't check write errors */
        if (write(c->fd,err,strlen(err)) == -1) {
            /* Nothing to do, Just to avoid the warning... */
        }
        server.stat_rejected_conn++;
        freeClient(c);
        return;
    }
    server.stat_numconnections++;
    c->flags |= flags;
}

// 用于TCP 接收请求的处理函数
void acceptTcpHandler(aeEventLoop *el, int fd, void *privdata, int mask) {
    int cport, cfd;
    char cip[REDIS_IP_STR_LEN];
    REDIS_NOTUSED(el);
    REDIS_NOTUSED(mask);
    REDIS_NOTUSED(privdata);

	// 接收客户端请求
    cfd = anetTcpAccept(server.neterr, fd, cip, sizeof(cip), &cport);
    if (cfd == ANET_ERR) {
        redisLog(REDIS_WARNING,"Accepting client connection: %s", server.neterr);
        return;
    }
    redisLog(REDIS_VERBOSE,"Accepted %s:%d", cip, cport);

	// 绑定I/O读事件回调
    acceptCommonHandler(cfd,0);
}

void acceptUnixHandler(aeEventLoop *el, int fd, void *privdata, int mask) {
    int cfd;
    REDIS_NOTUSED(el);
    REDIS_NOTUSED(mask);
    REDIS_NOTUSED(privdata);

    cfd = anetUnixAccept(server.neterr, fd);
    if (cfd == ANET_ERR) {
        redisLog(REDIS_WARNING,"Accepting client connection: %s", server.neterr);
        return;
    }
    redisLog(REDIS_VERBOSE,"Accepted connection to %s", server.unixsocket);

	// 为接收的套接字注册读I/O事件回调
    acceptCommonHandler(cfd,REDIS_UNIX_SOCKET);
}


static void freeClientArgv(redisClient *c) {
    int j;
    for (j = 0; j < c->argc; j++)
        decrRefCount(c->argv[j]);
    c->argc = 0;
    c->cmd = NULL;
}

/* Close all the slaves connections. This is useful in chained replication
 * when we resync with our own master and want to force all our slaves to
 * resync with us as well. */
void disconnectSlaves(void) {
    while (listLength(server.slaves)) {
        listNode *ln = listFirst(server.slaves);
        freeClient((redisClient*)ln->value);
    }
}

/* This function is called when the slave lose the connection with the
 * master into an unexpected way. */
void replicationHandleMasterDisconnection(void) {
    server.master = NULL;
    server.repl_state = REDIS_REPL_CONNECT;
    server.repl_down_since = server.unixtime;
    /* We lost connection with our master, force our slaves to resync
     * with us as well to load the new data set.
     *
     * If server.masterhost is NULL the user called SLAVEOF NO ONE so
     * slave resync is not needed. */
    if (server.masterhost != NULL) disconnectSlaves();
}

void freeClient(redisClient *c) {
    listNode *ln;

    /* If this is marked as current client unset it */
    if (server.current_client == c) server.current_client = NULL;

    /* If it is our master that's beging disconnected we should make sure
     * to cache the state to try a partial resynchronization later.
     *
     * Note that before doing this we make sure that the client is not in
     * some unexpected state, by checking its flags. */
    if (server.master && c->flags & REDIS_MASTER) {
        redisLog(REDIS_WARNING,"Connection with master lost.");
        if (!(c->flags & (REDIS_CLOSE_AFTER_REPLY|
                          REDIS_CLOSE_ASAP|
                          REDIS_BLOCKED|
                          REDIS_UNBLOCKED)))
        {
            replicationCacheMaster(c);
            return;
        }
    }

    /* Log link disconnection with slave */
    if ((c->flags & REDIS_SLAVE) && !(c->flags & REDIS_MONITOR)) {
        char ip[REDIS_IP_STR_LEN];

        if (anetPeerToString(c->fd,ip,sizeof(ip),NULL) != -1) {
            redisLog(REDIS_WARNING,"Connection with slave %s:%d lost.",
                ip, c->slave_listening_port);
        }
    }

    /* Free the query buffer */
    sdsfree(c->querybuf);
    c->querybuf = NULL;

    /* Deallocate structures used to block on blocking ops. */
    if (c->flags & REDIS_BLOCKED)
        unblockClientWaitingData(c);
    dictRelease(c->bpop.keys);

    /* UNWATCH all the keys */
    unwatchAllKeys(c);
    listRelease(c->watched_keys);

    /* Unsubscribe from all the pubsub channels */
    pubsubUnsubscribeAllChannels(c,0);
    pubsubUnsubscribeAllPatterns(c,0);
    dictRelease(c->pubsub_channels);
    listRelease(c->pubsub_patterns);

    /* Close socket, unregister events, and remove list of replies and
     * accumulated arguments. */
    if (c->fd != -1) {
        aeDeleteFileEvent(server.el,c->fd,AE_READABLE);
        aeDeleteFileEvent(server.el,c->fd,AE_WRITABLE);
        close(c->fd);
    }
    listRelease(c->reply);
    freeClientArgv(c);
#ifdef WIN32_IOCP
    aeWinCloseSocket(c->fd);
#else

#endif
    /* Remove from the list of clients */
    if (c->fd != -1) {
        ln = listSearchKey(server.clients,c);
        redisAssert(ln != NULL);
        listDelNode(server.clients,ln);
    }

    /* When client was just unblocked because of a blocking operation,
     * remove it from the list of unblocked clients. */
    if (c->flags & REDIS_UNBLOCKED) {
        ln = listSearchKey(server.unblocked_clients,c);
        redisAssert(ln != NULL);
        listDelNode(server.unblocked_clients,ln);
    }

    /* Master/slave cleanup Case 1:
     * we lost the connection with a slave. */
    if (c->flags & REDIS_SLAVE) {
        list *l;
        if (c->replstate == REDIS_REPL_SEND_BULK && c->repldbfd != -1) {
            close(c->repldbfd);
#ifdef _WIN32
            DeleteFileA(c->replFileCopy);
            memset(c->replFileCopy, 0, MAX_PATH);
#endif
        }
        l = (c->flags & REDIS_MONITOR) ? server.monitors : server.slaves;
        ln = listSearchKey(l,c);
        redisAssert(ln != NULL);
        listDelNode(l,ln);
        /* We need to remember the time when we started to have zero
         * attached slaves, as after some time we'll free the replication
         * backlog. */
        if (c->flags & REDIS_SLAVE && listLength(server.slaves) == 0)
            server.repl_no_slaves_since = server.unixtime;
        refreshGoodSlavesCount();
    }

    /* Master/slave cleanup Case 2:
     * we lost the connection with the master. */
    if (c->flags & REDIS_MASTER) replicationHandleMasterDisconnection();

    /* If this client was scheduled for async freeing we need to remove it
     * from the queue. */
    if (c->flags & REDIS_CLOSE_ASAP) {
        ln = listSearchKey(server.clients_to_close,c);
        redisAssert(ln != NULL);
        listDelNode(server.clients_to_close,ln);
    }

    /* Release other dynamically allocated client structure fields,
     * and finally release the client structure itself. */
    if (c->name) decrRefCount(c->name);
    zfree(c->argv);
    freeClientMultiState(c);
    zfree(c);
}

/* Schedule a client to free it at a safe time in the serverCron() function.
 * This function is useful when we need to terminate a client but we are in
 * a context where calling freeClient() is not possible, because the client
 * should be valid for the continuation of the flow of the program. */
void freeClientAsync(redisClient *c) {
    if (c->flags & REDIS_CLOSE_ASAP) return;
    c->flags |= REDIS_CLOSE_ASAP;
    listAddNodeTail(server.clients_to_close,c);
}

void freeClientsInAsyncFreeQueue(void) {
    while (listLength(server.clients_to_close)) {
        listNode *ln = listFirst(server.clients_to_close);
        redisClient *c = listNodeValue(ln);

        c->flags &= ~REDIS_CLOSE_ASAP;
        freeClient(c);
        listDelNode(server.clients_to_close,ln);
    }
}


#ifdef WIN32_IOCP
void sendReplyBufferDone(aeEventLoop *el, int fd, void *privdata, int written) {
    aeWinSendReq *req = (aeWinSendReq *)privdata;
    redisClient *c = (redisClient *)req->client;
    int offset = (int)(req->buf - (char *)req->data + written);
    REDIS_NOTUSED(el);
    REDIS_NOTUSED(fd);

    if (c->bufpos == offset) {
        c->bufpos = 0;
        c->sentlen = 0;
    }
    if (c->bufpos == 0 && listLength(c->reply) == 0) {
        aeDeleteFileEvent(server.el,c->fd,AE_WRITABLE);

        /* Close connection after entire reply has been sent. */
        if (c->flags & REDIS_CLOSE_AFTER_REPLY) {
            freeClientAsync(c);
        }
    }
}

void sendReplyListDone(aeEventLoop *el, int fd, void *privdata, int written) {
    aeWinSendReq *req = (aeWinSendReq *)privdata;
    redisClient *c = (redisClient *)req->client;
    robj *o = (robj *)req->data;
    REDIS_NOTUSED(el);
    REDIS_NOTUSED(fd);

    decrRefCount(o);

    if (c->bufpos == 0 && listLength(c->reply) == 0) {
        c->sentlen = 0;
        aeDeleteFileEvent(server.el,c->fd,AE_WRITABLE);

        /* Close connection after entire reply has been sent. */
        if (c->flags & REDIS_CLOSE_AFTER_REPLY){
            freeClientAsync(c);
        }
    }
}

void sendReplyToClient(aeEventLoop *el, int fd, void *privdata, int mask) {
    redisClient *c = (redisClient *)privdata;
    int nwritten = 0, totwritten = 0, objlen;
    size_t objmem;
    robj *o;
    int result = 0;
    listIter li;
    listNode *ln;
    REDIS_NOTUSED(el);
    REDIS_NOTUSED(mask);

#ifndef _WIN32
	if (c->flags & REDIS_MASTER) {
        /* do not send to master */
        c->bufpos = 0;
        c->sentlen = 0;
        while (listLength(c->reply)) {
            listDelNode(c->reply,listFirst(c->reply));
        }
        c->lastinteraction = time(NULL);
        return;
    }
#endif

    /* move list pointer to last one sent or first in list */
    listRewind(c->reply, &li);
    ln = listNext(&li);

    while(c->bufpos > c->sentlen || ln != NULL) {
		// 固定缓冲区的内容尚未发送完毕
        if (c->bufpos > c->sentlen) {
            nwritten = c->bufpos - c->sentlen;
			// 将缓冲区的内容写入fd中
            result = aeWinSocketSend(fd,c->buf+c->sentlen, nwritten,
                                        el, c, c->buf, sendReplyBufferDone);
			// 写失败，跳出循环
            if (result == SOCKET_ERROR && errno != WSA_IO_PENDING) {
                redisLog(REDIS_VERBOSE, "Error writing to client: %s", wsa_strerror(errno));
                freeClient(c);
                return;
            }
			// 更新发送的数据计数器
            c->sentlen += nwritten;
            totwritten += nwritten;

        } else { // 固定缓冲区的内容返回完毕，链表中需要返回的数据
			// 回复链表中第一个返回对象，计算器长度和内存大小
            o = listNodeValue(ln);
            objlen = (int)sdslen(o->ptr);
            objmem = zmalloc_size_sds(o->ptr);

			// 跳出空对象，并删除此对象
            if (objlen == 0) {
                listDelNode(c->reply,ln);
                ln = listNext(&li);
                continue;
            }

            /* object ref placed in request, release in sendReplyListDone */
			// 增加此返回回复对象的引用，在sendReplyListDone中进行释放
            incrRefCount(o);
			// 将内容写到fd中
            result = aeWinSocketSend(fd, ((char*)o->ptr), objlen, 
                                        el, c, o, sendReplyListDone);
            if (result == SOCKET_ERROR && errno != WSA_IO_PENDING) {
                redisLog(REDIS_VERBOSE,
                    "Error writing to client: %s", wsa_strerror(errno));
				// 写入失败，减少引用，释放客户端，跳出循环
                decrRefCount(o);
                freeClient(c);
                return;
            }

			// 更新发送数据的计数器
            totwritten += objlen;
            /* remove from list - object kept alive due to incrRefCount */
            listDelNode(c->reply,listFirst(c->reply));
            c->reply_bytes -= (unsigned long)objmem;
            ln = listNext(&li);
        }
        /* Note that we avoid to send more than REDIS_MAX_WRITE_PER_EVENT
         * bytes, in a single threaded server it's a good idea to serve
         * other clients as well, even if a very large request comes from
         * super fast link that is always able to accept data (in real world
         * scenario think about 'KEYS *' against the loopback interface).
         *
         * However if we are over the maxmemory limit we ignore that and
         * just deliver as much data as it is possible to deliver. */
		// 如果这次写的总量大于NET_MAX_WRITES_PER_EVENT的限制，则会中断本次的写操作，将处理时间让给其他的client，以免一个非常的回复独占服务器，剩余的数据下次继续在写
		// 但是，如果当服务器的内存数已经超过maxmemory，即使超过最大写NET_MAX_WRITES_PER_EVENT的限制，也会继续执行写入操作，是为了尽快写入给客户端
        if (totwritten > REDIS_MAX_WRITE_PER_EVENT &&
            (server.maxmemory == 0 ||
             zmalloc_used_memory() < server.maxmemory)) break;
    }
#ifndef _WIN32
	if (totwritten > 0) c->lastinteraction = server.unixtime;
#else
    if (totwritten > 0) { // 如果回复的内容不为空，更新其与客户端的交互时间
		/* For clients representing masters we don't count sending data
		* as an interaction, since we always send REPLCONF ACK commands
		* that take some time to just fill the socket output buffer.
		* We just rely on data / pings received for timeout detection. */
		if (!(c->flags & REDIS_MASTER)) c->lastinteraction = server.unixtime;
    }
#endif

}

#else
void sendReplyToClient(aeEventLoop *el, int fd, void *privdata, int mask) {
    redisClient *c = privdata;
    int nwritten = 0, totwritten = 0, objlen;
    size_t objmem;
    robj *o;
    REDIS_NOTUSED(el);
    REDIS_NOTUSED(mask);

    while(c->bufpos > 0 || listLength(c->reply)) {
        if (c->bufpos > 0) {

            nwritten = write(fd,c->buf+c->sentlen,c->bufpos-c->sentlen);
            if (nwritten <= 0) break;
            c->sentlen += nwritten;
            totwritten += nwritten;

            /* If the buffer was sent, set bufpos to zero to continue with
             * the remainder of the reply. */
            if (c->sentlen == c->bufpos) {
                c->bufpos = 0;
                c->sentlen = 0;
            }
        } else {
            o = listNodeValue(listFirst(c->reply));
            objlen = sdslen(o->ptr);
            objmem = zmalloc_size_sds(o->ptr);

            if (objlen == 0) {
                listDelNode(c->reply,listFirst(c->reply));
                continue;
            }

            nwritten = write(fd, ((char*)o->ptr)+c->sentlen,objlen-c->sentlen);
            if (nwritten <= 0) break;
            c->sentlen += nwritten;
            totwritten += nwritten;

            /* If we fully sent the object on head go to the next one */
            if (c->sentlen == objlen) {
                listDelNode(c->reply,listFirst(c->reply));
                c->sentlen = 0;
                c->reply_bytes -= objmem;
            }
        }
        /* Note that we avoid to send more than REDIS_MAX_WRITE_PER_EVENT
         * bytes, in a single threaded server it's a good idea to serve
         * other clients as well, even if a very large request comes from
         * super fast link that is always able to accept data (in real world
         * scenario think about 'KEYS *' against the loopback interface).
         *
         * However if we are over the maxmemory limit we ignore that and
         * just deliver as much data as it is possible to deliver. */
        if (totwritten > REDIS_MAX_WRITE_PER_EVENT &&
            (server.maxmemory == 0 ||
             zmalloc_used_memory() < server.maxmemory)) break;
    }
    if (nwritten == -1) {
        if (errno == EAGAIN) {
            nwritten = 0;
        } else {
            redisLog(REDIS_VERBOSE,
                "Error writing to client: %s", strerror(errno));
            freeClient(c);
            return;
        }
    }
    if (totwritten > 0) {
        /* For clients representing masters we don't count sending data
         * as an interaction, since we always send REPLCONF ACK commands
         * that take some time to just fill the socket output buffer.
         * We just rely on data / pings received for timeout detection. */
        if (!(c->flags & REDIS_MASTER)) c->lastinteraction = server.unixtime;
    }
    if (c->bufpos == 0 && listLength(c->reply) == 0) {
        c->sentlen = 0;
        aeDeleteFileEvent(server.el,c->fd,AE_WRITABLE);

        /* Close connection after entire reply has been sent. */
        if (c->flags & REDIS_CLOSE_AFTER_REPLY) freeClient(c);
    }
}
#endif

/* resetClient prepare the client to process the next command */
void resetClient(redisClient *c) {
    freeClientArgv(c);
    c->reqtype = 0;
    c->multibulklen = 0;
    c->bulklen = -1;
    /* We clear the ASKING flag as well if we are not inside a MULTI. */
    if (!(c->flags & REDIS_MULTI)) c->flags &= (~REDIS_ASKING);
}

int processInlineBuffer(redisClient *c) {
    char *newline;
    int argc, j;
    sds *argv, aux;
    size_t querylen;

    /* Search for end of line */
    newline = strchr(c->querybuf,'\n');

    /* Nothing to do without a \r\n */
    if (newline == NULL) {
        if (sdslen(c->querybuf) > REDIS_INLINE_MAX_SIZE) {
            addReplyError(c,"Protocol error: too big inline request");
            setProtocolError(c,0);
        }
        return REDIS_ERR;
    }

    /* Handle the \r\n case. */
    if (newline && newline != c->querybuf && *(newline-1) == '\r')
        newline--;

    /* Split the input buffer up to the \r\n */
    querylen = newline-(c->querybuf);
    aux = sdsnewlen(c->querybuf,querylen);
    argv = sdssplitargs(aux,&argc);
    sdsfree(aux);
    if (argv == NULL) {
        addReplyError(c,"Protocol error: unbalanced quotes in request");
        setProtocolError(c,0);
        return REDIS_ERR;
    }

    /* Newline from slaves can be used to refresh the last ACK time.
     * This is useful for a slave to ping back while loading a big
     * RDB file. */
    if (querylen == 0 && c->flags & REDIS_SLAVE)
        c->repl_ack_time = server.unixtime;

    /* Leave data after the first line of the query in the buffer */
    sdsrange(c->querybuf,querylen+2,-1);

    /* Setup argv array on client structure */
    if (c->argv) zfree(c->argv);
    c->argv = zmalloc(sizeof(robj*)*argc);

    /* Create redis objects for all arguments. */
    for (c->argc = 0, j = 0; j < argc; j++) {
        if (sdslen(argv[j])) {
            c->argv[c->argc] = createObject(REDIS_STRING,argv[j]);
            c->argc++;
        } else {
            sdsfree(argv[j]);
        }
    }
    zfree(argv);
    return REDIS_OK;
}

/* Helper function. Trims query buffer to make the function that processes
 * multi bulk requests idempotent. */
static void setProtocolError(redisClient *c, int pos) {
    if (server.verbosity >= REDIS_VERBOSE) {
        sds client = getClientInfoString(c);
        redisLog(REDIS_VERBOSE,
            "Protocol error from client: %s", client);
        sdsfree(client);
    }
    c->flags |= REDIS_CLOSE_AFTER_REPLY;
    sdsrange(c->querybuf,pos,-1);
}

// 解析命令的格式"*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n"
int processMultibulkBuffer(redisClient *c) {
    char *newline = NULL;
    int pos = 0, ok;
    long long ll;

	// 参数列表中的命令数量为0
    if (c->multibulklen == 0) {
        /* The client should have been reset */
        redisAssertWithInfo(c,NULL,c->argc == 0);

        /* Multi bulk length cannot be read without a \r\n */
		// 查询第一个换行符
        newline = strchr(c->querybuf,'\r');
        if (newline == NULL) { // 没有找到“\r\n”,表示不符合协议，返回错误
            if (sdslen(c->querybuf) > REDIS_INLINE_MAX_SIZE) {
                addReplyError(c,"Protocol error: too big mbulk count string");
                setProtocolError(c,0);
            }
            return REDIS_ERR;
        }

        /* Buffer should also contain \n */
		// 检查格式
        if (newline-(c->querybuf) > ((signed)sdslen(c->querybuf)-2))
            return REDIS_ERR;

        /* We know for sure there is a whole line since newline != NULL,
         * so go ahead and find out the multi bulk length. */
		// 保证第一个字符为“*”。*3\r\n
        redisAssertWithInfo(c,NULL,c->querybuf[0] == '*');
        ok = string2ll(c->querybuf+1,newline-(c->querybuf+1),&ll);
        if (!ok || ll > 1024*1024) {
            addReplyError(c,"Protocol error: invalid multibulk length");
            setProtocolError(c,pos);
            return REDIS_ERR;
        }

		// 指向"*3\r\n"的"\r\n"之后的位置
        pos = (newline-c->querybuf)+2;
		// 空白命令，则将之前的删除，保留未阅读的部分
        if (ll <= 0) {
            sdsrange(c->querybuf,pos,-1);
            return REDIS_OK;
        }

		// 参数数量
        c->multibulklen = (int)ll;

        /* Setup argv array on client structure */
		// 分配client参数列表空间
        if (c->argv) zfree(c->argv);
        c->argv = zmalloc(sizeof(robj*)*c->multibulklen);
    }

    redisAssertWithInfo(c,NULL,c->multibulklen > 0);
	// 读入multibulklen个参数，并创建参详保存在参数列表中
    while(c->multibulklen) {
        /* Read bulk length if unknown */
        if (c->bulklen == -1) {
			// 找到换行符，确保\r\n存在
            newline = strchr(c->querybuf+pos,'\r');
            if (newline == NULL) {
                if (sdslen(c->querybuf) > REDIS_INLINE_MAX_SIZE) {
                    addReplyError(c,"Protocol error: too big bulk count string");
                    setProtocolError(c,0);
                }
                break;
            }

            /* Buffer should also contain \n */
			// 检查格式
            if (newline-(c->querybuf) > ((signed)sdslen(c->querybuf)-2))
                break;

			// $3\r\nSET\r\n...，确保是'$'字符，保证格式
            if (c->querybuf[pos] != '$') {
                addReplyErrorFormat(c,
                    "Protocol error: expected '$', got '%c'",
                    c->querybuf[pos]);
                setProtocolError(c,pos);
                return REDIS_ERR;
            }

			// 将命令的长度保存到LL
            ok = string2ll(c->querybuf+pos+1,newline-(c->querybuf+pos+1),&ll);
            if (!ok || ll < 0 || ll > 512*1024*1024) {
                addReplyError(c,"Protocol error: invalid bulk length");
                setProtocolError(c,pos);
                return REDIS_ERR;
            }

			// 定位第一个参数的位置，也就是SET的S
            pos += newline-(c->querybuf+pos)+2;
			// 参数太长，进行优化
            if (ll >= REDIS_MBULK_BIG_ARG) {
                size_t qblen;

                /* If we are going to read a large object from network
                 * try to make it likely that it will start at c->querybuf
                 * boundary so that we can optimize object creation
                 * avoiding a large copy of data. */
				// 如果我们要从网络中读取一个大的对象，尝试使它可能从c-> querybuf边界开始，
				// 以便我们可以优化对象创建，避免大量的数据副本
				// 保存未读取的部分
                sdsrange(c->querybuf,pos,-1);
				// 重置偏移量
                pos = 0;
				// 获取querybuf已经使用的长度
                qblen = sdslen(c->querybuf);
                /* Hint the sds library about the amount of bytes this string is
                 * going to contain. */
				// 扩展querybuf的大小
                if (qblen < ll+2)
                    c->querybuf = sdsMakeRoomFor(c->querybuf,ll+2-qblen);
            }
			// 保存参数的长度
            c->bulklen = ll;
        }

        /* Read bulk argument */
		// 因为只读了multibulklen字节的数据，读到的数据不够，则直接跳出循环，执行processInputBuffer()函数循环读取
        if (sdslen(c->querybuf)-pos < (unsigned)(c->bulklen+2)) {
            /* Not enough data (+2 == trailing \r\n) */
            break;
        } else {
            /* Optimization: if the buffer contains JUST our bulk element
             * instead of creating a new object by *copying* the sds we
             * just use the current sds string. */
			// 如果读入的长度大于32k
            if (pos == 0 &&
                c->bulklen >= REDIS_MBULK_BIG_ARG &&
                (signed) sdslen(c->querybuf) == c->bulklen+2)
            {
                c->argv[c->argc++] = createObject(REDIS_STRING,c->querybuf);
				// 跳过换行
                sdsIncrLen(c->querybuf,-2); /* remove CRLF */
                c->querybuf = sdsempty();
                /* Assume that if we saw a fat argument we'll see another one
                 * likely... */
				// 设置一个新长度
                c->querybuf = sdsMakeRoomFor(c->querybuf,c->bulklen+2);
                pos = 0;
				// 创建对象保存在client的参数列表
            } else {
                c->argv[c->argc++] =
                    createStringObject(c->querybuf+pos,c->bulklen);
                pos += c->bulklen+2;
            }
			// 清空命令内容的长度
            c->bulklen = -1;
			// 未读取命令参数的数量，读取一个，该值减1
            c->multibulklen--;
        }
    }

    /* Trim to pos */
	// 删除已经读取的，保留未读取的
    if (pos) sdsrange(c->querybuf,pos,-1);

    /* We're done when c->multibulk == 0 */
	// 命令的参数全部被读取完
    if (c->multibulklen == 0) return REDIS_OK;

    /* Still not read to process the command */
    return REDIS_ERR;
}

void processInputBuffer(redisClient *c) {
    /* Keep processing while there is something in the input buffer */
	// 一直读入缓冲区的内容
    while(sdslen(c->querybuf)) {
        /* Immediately abort if the client is in the middle of something. */
		// 如果客户端处于被堵塞状态，直接返回
        if (c->flags & REDIS_BLOCKED) return;

        /* REDIS_CLOSE_AFTER_REPLY closes the connection once the reply is
         * written to the client. Make sure to not let the reply grow after
         * this flag has been set (i.e. don't process more commands). */
		// 如果客户端处于管斌状态，则直接返回
        if (c->flags & REDIS_CLOSE_AFTER_REPLY) return;

        /* Determine request type when unknown. */
		// 如果是未知的请求类型，则判定请求类型
        if (!c->reqtype) {
            if (c->querybuf[0] == '*') {
				// 如果是“*”开头，则是多条请求，是client发来的
                c->reqtype = REDIS_REQ_MULTIBULK;
            } else {
				// 否则就是内联请求，是Telnet发来的
                c->reqtype = REDIS_REQ_INLINE;
            }
        }

		// 如果是内联请求
        if (c->reqtype == REDIS_REQ_INLINE) {
            if (processInlineBuffer(c) != REDIS_OK) break;
			// 如果是多条请求
        } else if (c->reqtype == REDIS_REQ_MULTIBULK) {
            if (processMultibulkBuffer(c) != REDIS_OK) break;
        } else {
            redisPanic("Unknown request type");
        }

        /* Multibulk processing could see a <= 0 length. */
		// 如果参数的个数是0，则重置client
        if (c->argc == 0) {
            resetClient(c);
        } else {
            /* Only reset the client when the command was executed. */
			// 执行命令成功或，重置client
            if (processCommand(c) == REDIS_OK)
                resetClient(c);
        }
    }
}

// 为客户端连接的套接字，注册读事件回调 readQueryFromClient
// 读取输入缓冲区的内容
void readQueryFromClient(aeEventLoop *el, int fd, void *privdata, int mask) {
    redisClient *c = (redisClient*) privdata;
    int nread, readlen;
    size_t qblen;
    REDIS_NOTUSED(el);
    REDIS_NOTUSED(mask);

    server.current_client = c;
	// 读入的长度,默认大小是16KB
    readlen = REDIS_IOBUF_LEN;
    /* If this is a multi bulk request, and we are processing a bulk reply
     * that is large enough, try to maximize the probability that the query
     * buffer contains exactly the SDS string representing the object, even
     * at the risk of requiring more read(2) calls. This way the function
     * processMultiBulkBuffer() can avoid copying buffers to create the
     * Redis Object representing the argument. */
	// 如果是多条请求，将会根据请求的大小，设置读入的长度
    if (c->reqtype == REDIS_REQ_MULTIBULK && c->multibulklen && c->bulklen != -1
        && c->bulklen >= REDIS_MBULK_BIG_ARG)
    {
		// 剩余
        int remaining = (int)((unsigned)(c->bulklen+2)-sdslen(c->querybuf));

        if (remaining < readlen) readlen = remaining;
    }

	// 输入缓冲区的长度
    qblen = sdslen(c->querybuf);
	// 记录输入缓冲区的峰值
    if (c->querybuf_peak < qblen) c->querybuf_peak = qblen;
	// 扩展输入缓冲区的大小
    c->querybuf = sdsMakeRoomFor(c->querybuf, readlen);
	// 将client命令，读入到输入缓冲区
    nread = read(fd, c->querybuf+qblen, readlen);

    if (nread == -1) { // 读操作出错
        if (errno == EAGAIN) {
            nread = 0;
        } else {
#ifdef _WIN32
            redisLog(REDIS_VERBOSE, "Reading from client: %s",wsa_strerror(errno));
#else
            redisLog(REDIS_VERBOSE, "Reading from client: %s",strerror(errno));
#endif
            freeClient(c);
            return;
        }
    } else if (nread == 0) { // 读操作完成
        redisLog(REDIS_VERBOSE, "Client closed connection");
        freeClient(c);
        return;
    }
#ifdef WIN32_IOCP
    aeWinReceiveDone(fd); // 提交读请求，以备能够继续读取数据
#endif
    if (nread) {
        sdsIncrLen(c->querybuf,nread); // 更新输入缓冲区的已用大小、未用大小
        c->lastinteraction = server.unixtime; // 设置最后一次，客户端和server的交互时间
        if (c->flags & REDIS_MASTER) c->reploff += nread; // 如果是主节点，更新复制节点的偏移量
    } else {
        server.current_client = NULL;
        return;
    }

	// 如果输入缓冲区的长度超过服务器设置的最大缓冲区的长度,超过最大长度，则退出
    if (sdslen(c->querybuf) > server.client_max_querybuf_len) {
		// 将client输入的信息转换为sds
        sds ci = getClientInfoString(c), bytes = sdsempty();
		// 输入缓冲区保存于bytes中
        bytes = sdscatrepr(bytes,c->querybuf,64);
        redisLog(REDIS_WARNING,"Closing client that reached max query buffer length: %s (qbuf initial bytes: %s)", ci, bytes);
		// 释放空间
        sdsfree(ci);
        sdsfree(bytes);
        freeClient(c);
        return;
    }
    processInputBuffer(c);
    server.current_client = NULL;
}
//https://blog.csdn.net/men_wen/article/details/72084617

void getClientsMaxBuffers(unsigned long *longest_output_list,
                          unsigned long *biggest_input_buffer) {
    redisClient *c;
    listNode *ln;
    listIter li;
    unsigned long lol = 0, bib = 0;

    listRewind(server.clients,&li);
    while ((ln = listNext(&li)) != NULL) {
        c = listNodeValue(ln);

        if (listLength(c->reply) > lol) lol = listLength(c->reply);
        if (sdslen(c->querybuf) > bib) bib = (unsigned long)sdslen(c->querybuf);
    }
    *longest_output_list = lol;
    *biggest_input_buffer = bib;
}

/* This is a helper function for getClientPeerId().
 * It writes the specified ip/port to "peerid" as a null termiated string
 * in the form ip:port if ip does not contain ":" itself, otherwise
 * [ip]:port format is used (for IPv6 addresses basically). */
void formatPeerId(char *peerid, size_t peerid_len, char *ip, int port) {
    if (strchr(ip,':'))
        snprintf(peerid,peerid_len,"[%s]:%d",ip,port);
    else
        snprintf(peerid,peerid_len,"%s:%d",ip,port);
}

/* A Redis "Peer ID" is a colon separated ip:port pair.
 * For IPv4 it's in the form x.y.z.k:pork, example: "127.0.0.1:1234".
 * For IPv6 addresses we use [] around the IP part, like in "[::1]:1234".
 * For Unix socekts we use path:0, like in "/tmp/redis:0".
 *
 * A Peer ID always fits inside a buffer of REDIS_PEER_ID_LEN bytes, including
 * the null term.
 *
 * The function returns REDIS_OK on succcess, and REDIS_ERR on failure.
 *
 * On failure the function still populates 'peerid' with the "?:0" string
 * in case you want to relax error checking or need to display something
 * anyway (see anetPeerToString implementation for more info). */
int getClientPeerId(redisClient *client, char *peerid, size_t peerid_len) {
    char ip[REDIS_IP_STR_LEN];
    int port;

    if (client->flags & REDIS_UNIX_SOCKET) {
        /* Unix socket client. */
        snprintf(peerid,peerid_len,"%s:0",server.unixsocket);
        return REDIS_OK;
    } else {
        /* TCP client. */
        int retval = anetPeerToString(client->fd,ip,sizeof(ip),&port);
#ifndef _WIN32
		formatPeerId(peerid,peerid_len,ip,port);
#else
        if (retval == -1 && client->flags & REDIS_MASTER) {
            formatPeerId(peerid, peerid_len, "MASTER", 0);
            retval = 0;
        } else {
            formatPeerId(peerid,peerid_len,ip,port);
        }
#endif
        return (retval == -1) ? REDIS_ERR : REDIS_OK;
    }
}

/* Turn a Redis client into an sds string representing its state. */
sds getClientInfoString(redisClient *client) {
    char peerid[REDIS_PEER_ID_LEN], flags[16], events[3], *p;
    int emask;

    getClientPeerId(client,peerid,sizeof(peerid));
    p = flags;
    if (client->flags & REDIS_SLAVE) {
        if (client->flags & REDIS_MONITOR)
            *p++ = 'O';
        else
            *p++ = 'S';
    }
    if (client->flags & REDIS_MASTER) *p++ = 'M';
    if (client->flags & REDIS_MULTI) *p++ = 'x';
    if (client->flags & REDIS_BLOCKED) *p++ = 'b';
    if (client->flags & REDIS_DIRTY_CAS) *p++ = 'd';
    if (client->flags & REDIS_CLOSE_AFTER_REPLY) *p++ = 'c';
    if (client->flags & REDIS_UNBLOCKED) *p++ = 'u';
    if (client->flags & REDIS_CLOSE_ASAP) *p++ = 'A';
    if (client->flags & REDIS_UNIX_SOCKET) *p++ = 'U';
    if (p == flags) *p++ = 'N';
    *p++ = '\0';

    emask = client->fd == -1 ? 0 : aeGetFileEvents(server.el,client->fd);
    p = events;
    if (emask & AE_READABLE) *p++ = 'r';
    if (emask & AE_WRITABLE) *p++ = 'w';
    *p = '\0';
    return sdscatprintf(sdsempty(),
        "addr=%s fd=%d name=%s age=%ld idle=%ld flags=%s db=%d sub=%d psub=%d multi=%d qbuf=%lu qbuf-free=%lu obl=%lu oll=%lu omem=%lu events=%s cmd=%s",
        peerid,
        client->fd,
        client->name ? (char*)client->name->ptr : "",
        (long)(server.unixtime - client->ctime),
        (long)(server.unixtime - client->lastinteraction),
        flags,
        client->db->id,
        (int) dictSize(client->pubsub_channels),
        (int) listLength(client->pubsub_patterns),
        (client->flags & REDIS_MULTI) ? client->mstate.count : -1,
        (unsigned long) sdslen(client->querybuf),
        (unsigned long) sdsavail(client->querybuf),
        (unsigned long) client->bufpos,
        (unsigned long) listLength(client->reply),
        getClientOutputBufferMemoryUsage(client),
        events,
        client->lastcmd ? client->lastcmd->name : "NULL");
}

sds getAllClientsInfoString(void) {
    listNode *ln;
    listIter li;
    redisClient *client;
    sds o = sdsempty();

    listRewind(server.clients,&li);
    while ((ln = listNext(&li)) != NULL) {
        sds cs;

        client = listNodeValue(ln);
        cs = getClientInfoString(client);
        o = sdscatsds(o,cs);
        sdsfree(cs);
        o = sdscatlen(o,"\n",1);
    }
    return o;
}

void clientCommand(redisClient *c) {
    listNode *ln;
    listIter li;
    redisClient *client;

    if (!strcasecmp(c->argv[1]->ptr,"list") && c->argc == 2) {
        sds o = getAllClientsInfoString();
        addReplyBulkCBuffer(c,o,sdslen(o));
        sdsfree(o);
    } else if (!strcasecmp(c->argv[1]->ptr,"kill") && c->argc == 3) {
        listRewind(server.clients,&li);
        while ((ln = listNext(&li)) != NULL) {
            char peerid[REDIS_PEER_ID_LEN];

            client = listNodeValue(ln);
            if (getClientPeerId(client,peerid,sizeof(peerid)) == REDIS_ERR)
                continue;
            if (strcmp(peerid,c->argv[2]->ptr) == 0) {
                addReply(c,shared.ok);
                if (c == client) {
                    client->flags |= REDIS_CLOSE_AFTER_REPLY;
                } else {
                    freeClient(client);
                }
                return;
            }
        }
        addReplyError(c,"No such client");
    } else if (!strcasecmp(c->argv[1]->ptr,"setname") && c->argc == 3) {
        int j, len = sdslen(c->argv[2]->ptr);
        char *p = c->argv[2]->ptr;

        /* Setting the client name to an empty string actually removes
         * the current name. */
        if (len == 0) {
            if (c->name) decrRefCount(c->name);
            c->name = NULL;
            addReply(c,shared.ok);
            return;
        }

        /* Otherwise check if the charset is ok. We need to do this otherwise
         * CLIENT LIST format will break. You should always be able to
         * split by space to get the different fields. */
        for (j = 0; j < len; j++) {
            if (p[j] < '!' || p[j] > '~') { /* ASCII is assumed. */
                addReplyError(c,
                    "Client names cannot contain spaces, "
                    "newlines or special characters.");
                return;
            }
        }
        if (c->name) decrRefCount(c->name);
        c->name = c->argv[2];
        incrRefCount(c->name);
        addReply(c,shared.ok);
    } else if (!strcasecmp(c->argv[1]->ptr,"getname") && c->argc == 2) {
        if (c->name)
            addReplyBulk(c,c->name);
        else
            addReply(c,shared.nullbulk);
    } else {
        addReplyError(c, "Syntax error, try CLIENT (LIST | KILL ip:port | GETNAME | SETNAME connection-name)");
    }
}

/* Rewrite the command vector of the client. All the new objects ref count
 * is incremented. The old command vector is freed, and the old objects
 * ref count is decremented. */
void rewriteClientCommandVector(redisClient *c, int argc, ...) {
    va_list ap;
    int j;
    robj **argv; /* The new argument vector */

    argv = zmalloc(sizeof(robj*)*argc);
    va_start(ap,argc);
    for (j = 0; j < argc; j++) {
        robj *a;
        
        a = va_arg(ap, robj*);
        argv[j] = a;
        incrRefCount(a);
    }
    /* We free the objects in the original vector at the end, so we are
     * sure that if the same objects are reused in the new vector the
     * refcount gets incremented before it gets decremented. */
    for (j = 0; j < c->argc; j++) decrRefCount(c->argv[j]);
    zfree(c->argv);
    /* Replace argv and argc with our new versions. */
    c->argv = argv;
    c->argc = argc;
    c->cmd = lookupCommandOrOriginal(c->argv[0]->ptr);
    redisAssertWithInfo(c,NULL,c->cmd != NULL);
    va_end(ap);
}

/* Rewrite a single item in the command vector.
 * The new val ref count is incremented, and the old decremented. */
void rewriteClientCommandArgument(redisClient *c, int i, robj *newval) {
    robj *oldval;
   
    redisAssertWithInfo(c,NULL,i < c->argc);
    oldval = c->argv[i];
    c->argv[i] = newval;
    incrRefCount(newval);
    decrRefCount(oldval);

    /* If this is the command name make sure to fix c->cmd. */
    if (i == 0) {
        c->cmd = lookupCommandOrOriginal(c->argv[0]->ptr);
        redisAssertWithInfo(c,NULL,c->cmd != NULL);
    }
}

/* This function returns the number of bytes that Redis is virtually
 * using to store the reply still not read by the client.
 * It is "virtual" since the reply output list may contain objects that
 * are shared and are not really using additional memory.
 *
 * The function returns the total sum of the length of all the objects
 * stored in the output list, plus the memory used to allocate every
 * list node. The static reply buffer is not taken into account since it
 * is allocated anyway.
 *
 * Note: this function is very fast so can be called as many time as
 * the caller wishes. The main usage of this function currently is
 * enforcing the client output length limits. */
unsigned long getClientOutputBufferMemoryUsage(redisClient *c) {
    unsigned long list_item_size = sizeof(listNode)+sizeof(robj);

    return c->reply_bytes + (list_item_size*listLength(c->reply));
}

/* Get the class of a client, used in order to enforce limits to different
 * classes of clients.
 *
 * The function will return one of the following:
 * REDIS_CLIENT_LIMIT_CLASS_NORMAL -> Normal client
 * REDIS_CLIENT_LIMIT_CLASS_SLAVE  -> Slave or client executing MONITOR command
 * REDIS_CLIENT_LIMIT_CLASS_PUBSUB -> Client subscribed to Pub/Sub channels
 */
int getClientLimitClass(redisClient *c) {
    if (c->flags & REDIS_SLAVE) return REDIS_CLIENT_LIMIT_CLASS_SLAVE;
    if (dictSize(c->pubsub_channels) || listLength(c->pubsub_patterns))
        return REDIS_CLIENT_LIMIT_CLASS_PUBSUB;
    return REDIS_CLIENT_LIMIT_CLASS_NORMAL;
}

int getClientLimitClassByName(char *name) {
    if (!strcasecmp(name,"normal")) return REDIS_CLIENT_LIMIT_CLASS_NORMAL;
    else if (!strcasecmp(name,"slave")) return REDIS_CLIENT_LIMIT_CLASS_SLAVE;
    else if (!strcasecmp(name,"pubsub")) return REDIS_CLIENT_LIMIT_CLASS_PUBSUB;
    else return -1;
}

char *getClientLimitClassName(int class) {
    switch(class) {
    case REDIS_CLIENT_LIMIT_CLASS_NORMAL:   return "normal";
    case REDIS_CLIENT_LIMIT_CLASS_SLAVE:    return "slave";
    case REDIS_CLIENT_LIMIT_CLASS_PUBSUB:   return "pubsub";
    default:                                return NULL;
    }
}

/* The function checks if the client reached output buffer soft or hard
 * limit, and also update the state needed to check the soft limit as
 * a side effect.
 *
 * Return value: non-zero if the client reached the soft or the hard limit.
 *               Otherwise zero is returned. */
int checkClientOutputBufferLimits(redisClient *c) {
    int soft = 0, hard = 0, class;
    unsigned long used_mem = getClientOutputBufferMemoryUsage(c);

    class = getClientLimitClass(c);
    if (server.client_obuf_limits[class].hard_limit_bytes &&
        used_mem >= server.client_obuf_limits[class].hard_limit_bytes)
        hard = 1;
    if (server.client_obuf_limits[class].soft_limit_bytes &&
        used_mem >= server.client_obuf_limits[class].soft_limit_bytes)
        soft = 1;

    /* We need to check if the soft limit is reached continuously for the
     * specified amount of seconds. */
    if (soft) {
        if (c->obuf_soft_limit_reached_time == 0) {
            c->obuf_soft_limit_reached_time = server.unixtime;
            soft = 0; /* First time we see the soft limit reached */
        } else {
            time_t elapsed = server.unixtime - c->obuf_soft_limit_reached_time;

            if (elapsed <=
                server.client_obuf_limits[class].soft_limit_seconds) {
                soft = 0; /* The client still did not reached the max number of
                             seconds for the soft limit to be considered
                             reached. */
            }
        }
    } else {
        c->obuf_soft_limit_reached_time = 0;
    }
    return soft || hard;
}

/* Asynchronously close a client if soft or hard limit is reached on the
 * output buffer size. The caller can check if the client will be closed
 * checking if the client REDIS_CLOSE_ASAP flag is set.
 *
 * Note: we need to close the client asynchronously because this function is
 * called from contexts where the client can't be freed safely, i.e. from the
 * lower level functions pushing data inside the client output buffers. */
void asyncCloseClientOnOutputBufferLimitReached(redisClient *c) {
    redisAssert(c->reply_bytes < ULONG_MAX-(1024*64));
    if (c->reply_bytes == 0 || c->flags & REDIS_CLOSE_ASAP) return;
    if (checkClientOutputBufferLimits(c)) {
        sds client = getClientInfoString(c);

        freeClientAsync(c);
        redisLog(REDIS_WARNING,"Client %s scheduled to be closed ASAP for overcoming of output buffer limits.", client);
        sdsfree(client);
    }
}

/* Helper function used by freeMemoryIfNeeded() in order to flush slaves
 * output buffers without returning control to the event loop. */
void flushSlavesOutputBuffers(void) {
    listIter li;
    listNode *ln;

    listRewind(server.slaves,&li);
    while((ln = listNext(&li))) {
        redisClient *slave = listNodeValue(ln);
        int events;

        events = aeGetFileEvents(server.el,slave->fd);
        if (events & AE_WRITABLE &&
            slave->replstate == REDIS_REPL_ONLINE &&
            listLength(slave->reply))
        {
            sendReplyToClient(server.el,slave->fd,slave,0);
        }
    }
}
