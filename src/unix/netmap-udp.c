/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "uv.h"
#include "internal.h"

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#if defined(__MVS__)
#include <xti.h>
#endif
#include <sys/un.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>


static uint16_t ip_checksum(struct ip* ip);
static void uv__udp_netmap_recv_packet(uv_loop_t* loop, struct netmap_slot* slot, uint8_t* p);
static size_t uv__udp_netmap_generate_udp(uv_loop_t* loop, unsigned int src_port, struct msghdr* h, uint8_t* pkt);
static int uv__udp_netmap_send_udp(uv_loop_t* loop, uv_udp_send_t* req, struct netmap_ring* ring);
static void uv__udp_netmap_run_completed(uv_loop_t* loop);
static void uv__udp_netmap_io(uv_loop_t* loop, uv__io_t* w, unsigned int revents);

static const size_t ETH_LEN = sizeof(struct ether_header);
static const size_t ETH_IP_LEN = ETH_LEN + sizeof(struct ip);
static const size_t ETH_IP_UDP_LEN = ETH_IP_LEN + sizeof(struct udphdr);


static uint16_t ip_checksum(struct ip* ip) {
  int sum = 0;
  size_t len = sizeof(struct ip);
  size_t i;
  size_t len_2 = len/2;

  for (i = 0; i < len_2; i++) {
    sum += *((uint16_t*)(ip) + i);
  }

  if (len_2 * 2 != len) {
    sum += *((uint8_t*)(ip) + (len - 1));
  }

  while (sum > USHRT_MAX) {
    sum -= USHRT_MAX;
  }

  return USHRT_MAX - sum;
}

static uint16_t udp_checksum(struct ip* ip, struct udphdr* udp, uint8_t* payload, size_t payload_len) {
  int sum;
  int i;

  sum = 0;
  sum += *((uint16_t*)(&ip->ip_src.s_addr));
  sum += *((uint16_t*)(&ip->ip_src.s_addr) + 1);
  sum += *((uint16_t*)(&ip->ip_dst.s_addr));
  sum += *((uint16_t*)(&ip->ip_dst.s_addr) + 1);
  sum += htons(ip->ip_p);
  sum += udp->len;

  sum += udp->source;
  sum += udp->dest;
  sum += udp->len;

  for (i = 0; i < payload_len / 2; ++i) {
    sum += *((uint16_t*)(payload) + i);
  }

  if (payload_len % 2 == 1) {
    sum += *((uint8_t*)(payload) + (payload_len - 1));
  }

  while (sum > USHRT_MAX) {
    sum -= USHRT_MAX;
  }

  return USHRT_MAX - sum;
}


static void uv__udp_netmap_recv_packet(uv_loop_t* loop, struct netmap_slot* slot, uint8_t* p) {
  struct ether_header* eth;
  struct ip* ip;
  struct udphdr* udp;
  uint8_t* payload;
  uint16_t dest_port;
  uint16_t udp_len;
  size_t payload_len;
  uint16_t udp_chksum;

  if (slot->len < ETH_IP_UDP_LEN) {
    return;
  }

  eth = (struct ether_header*)p;

  if (eth->ether_type != htons(ETHERTYPE_IP)) {
    return;
  }

  ip = (struct ip*)(p + ETH_LEN);

  if (ip->ip_p != IPPROTO_UDP) {
    return;
  }

  udp = (struct udphdr*)(p + ETH_IP_LEN);

  // todo: verify ip->ip_sum
  // todo: verify ip->ip_hl
  // todo: verify ip->ip_len
  dest_port = ntohs(udp->dest);
  udp_len = ntohs(udp->len) - sizeof(*udp);
  payload_len = slot->len - ETH_IP_UDP_LEN;
  payload_len = payload_len < udp_len ? payload_len : udp_len;
  payload = p + ETH_IP_UDP_LEN;

  udp_chksum = udp->check;
  if (udp_chksum != udp_checksum(ip, udp, payload, payload_len)) {
    printf("udp checksum failed, %x != %x\n", udp_chksum, udp_checksum(ip, udp, payload, payload_len));
    return;
  }

  if (loop->netmap->sockets[dest_port]) {
    struct sockaddr_in addr;
    uv_buf_t buf = uv_buf_init(NULL, 0);
    uv_udp_t* socket_handle = loop->netmap->sockets[dest_port];
    socket_handle->alloc_cb((uv_handle_t*) socket_handle, 64 * 1024, &buf);

    if (buf.base == NULL || buf.len == 0) {
      socket_handle->recv_cb(socket_handle, UV_ENOBUFS, &buf, NULL, 0);
      return;
    }
    assert(buf.base != NULL);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = udp->source;
    addr.sin_addr.s_addr = ip->ip_src.s_addr;

    memcpy(buf.base, payload, payload_len);

    socket_handle->recv_cb(socket_handle, payload_len, &buf, (const struct sockaddr*)&addr, 0);
  }
}

static size_t uv__udp_netmap_generate_udp(uv_loop_t* loop, unsigned int src_port, struct msghdr* h, uint8_t* pkt) {
  // extract sockaddr_in from h, apply to pkt
  struct ether_header* eth;
  struct ip* ip;
  struct udphdr* udp;
  struct sockaddr* sockaddr;
  struct sockaddr_in* inaddr;
  size_t payload_len;
  size_t i;
  uint8_t* payload;

  sockaddr = (struct sockaddr*)h->msg_name;
  assert(sockaddr->sa_family == AF_INET);
  inaddr = (struct sockaddr_in*)h->msg_name;

  payload_len = 0;
  for (i = 0; i < h->msg_iovlen; i++) {
    payload_len += h->msg_iov[i].iov_len;
  }

  eth = (struct ether_header*)pkt;
  memset(eth, 0, sizeof(*eth));
  memcpy(eth->ether_dhost, loop->netmap->dst_mac, sizeof(eth->ether_dhost));
  memcpy(eth->ether_shost, loop->netmap->src_mac, sizeof(eth->ether_shost));
  eth->ether_type = htons(ETHERTYPE_IP);

  ip = (struct ip*)(pkt + ETH_LEN);
  memset(ip, 0, sizeof(*ip));
  ip->ip_v = IPVERSION;
  // this length (ip_hl) is a bit weird, basically we signal whether we use IP extensions here
  // the length is denominated in 4-byte chunks
  ip->ip_hl = sizeof(*ip) >> 2;
  ip->ip_tos = loop->netmap->socket_tos[src_port];
  ip->ip_len = htons(sizeof(*ip) + sizeof(*udp) + payload_len);
  ip->ip_id = 0;
  ip->ip_off = htons(IP_DF);
  ip->ip_ttl = IPDEFTTL;
  ip->ip_p = IPPROTO_UDP;
  memcpy(&ip->ip_src.s_addr, loop->netmap->src_ip, sizeof(ip->ip_src.s_addr));
  ip->ip_dst.s_addr = inaddr->sin_addr.s_addr;
  ip->ip_sum = ip_checksum(ip);

  udp = (struct udphdr*)(pkt + ETH_IP_LEN);
  memset(udp, 0, sizeof(*udp));
  udp->source = htons(src_port);
  udp->dest = inaddr->sin_port;
  udp->len = htons(sizeof(*udp) + payload_len);
  udp->check = 0;

  payload = pkt + ETH_IP_UDP_LEN;
  for (i = 0; i < h->msg_iovlen; i++) {
    memcpy(payload, h->msg_iov[i].iov_base, h->msg_iov[i].iov_len);
    payload += h->msg_iov[i].iov_len;
  }

  udp->check = udp_checksum(ip, udp, pkt + ETH_IP_UDP_LEN, payload_len);

  return ETH_IP_UDP_LEN + payload_len;
}

static int uv__udp_netmap_send_udp(uv_loop_t* loop, uv_udp_send_t* req, struct netmap_ring* ring) {
    struct netmap_slot* slot;
    uint8_t* p;
    struct msghdr h;
    int src_port;

    if (nm_ring_empty(ring)) {
      return -1;
    }

    slot = &ring->slot[ring->head];
    p = (uint8_t*)NETMAP_BUF(ring, slot->buf_idx);

    memset(&h, 0, sizeof(h));
    h.msg_name = &req->addr;
    h.msg_namelen = (req->addr.ss_family == AF_INET6 ?
      sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
    h.msg_iov = (struct iovec*) req->bufs;
    h.msg_iovlen = req->nbufs;

    src_port = req->handle->io_watcher.fd;

    slot->len = uv__udp_netmap_generate_udp(loop, src_port, &h, p);
    req->status = slot->len - ETH_IP_UDP_LEN;

    QUEUE_REMOVE(&req->queue);
    QUEUE_INSERT_TAIL(&loop->netmap->write_completed_queue, &req->queue);

    ring->head = ring->cur = nm_ring_next(ring, ring->cur);

    return 0;
}

static void uv__udp_netmap_run_completed(uv_loop_t* loop) {
  uv_udp_send_t* req;
  QUEUE* q;
  int removed;

  loop->netmap->flags |= UV_HANDLE_UDP_PROCESSING;
  removed = !QUEUE_EMPTY(&loop->netmap->write_completed_queue);

  while (!QUEUE_EMPTY(&loop->netmap->write_completed_queue)) {
    q = QUEUE_HEAD(&loop->netmap->write_completed_queue);
    QUEUE_REMOVE(q);

    req = QUEUE_DATA(q, uv_udp_send_t, queue);
    uv__req_unregister(loop, req);

    if (req->bufs != req->bufsml)
      uv__free(req->bufs);
    req->bufs = NULL;

    if (req->send_cb == NULL)
      continue;

    if (req->status >= 0)
      req->send_cb(req, 0);
    else
      req->send_cb(req, req->status);
  }

  if (QUEUE_EMPTY(&loop->netmap->write_queue) && !removed) {
    uv__io_stop(loop, &loop->netmap->io_watcher, POLLOUT);
    if (!uv__io_active(&loop->netmap->io_watcher, POLLIN)) {
      uv__handle_stop(loop->netmap);
    }
  }

  loop->netmap->flags &= ~UV_HANDLE_UDP_PROCESSING;
}

static void uv__udp_netmap_io(uv_loop_t* loop, uv__io_t* w, unsigned int revents) {
  int i;
  uint64_t j, len;
  struct netmap_ring* ring;

  if (loop->netmap == NULL) {
    return;
  }
  if (revents & POLLIN) {
    for (i = loop->netmap->intf->first_rx_ring; i <= loop->netmap->intf->last_rx_ring; i++) {
      ring = NETMAP_RXRING(loop->netmap->intf->nifp, i);

      len = nm_ring_space(ring);
      // todo consider limiting len here so that we can run timers etc
      for (j = 0; j < len; j++) {
        struct netmap_slot* slot;
        uint8_t* p;

        slot = &ring->slot[ring->cur];
        p = (uint8_t*)NETMAP_BUF(ring, slot->buf_idx);

        uv__udp_netmap_recv_packet(loop, slot, p);

        ring->head = ring->cur = nm_ring_next(ring, ring->cur);
      }
    }
  }

  if ((revents & POLLOUT)) {
    // only tx on our rx ring, and only tx for as long as there's room to do so
    for (i = loop->netmap->intf->first_rx_ring; i <= loop->netmap->intf->last_rx_ring; i++) {
      uint64_t pkt_num;

      ring = NETMAP_TXRING(loop->netmap->intf->nifp, i);
      len = nm_ring_space(ring);
      pkt_num = 0;
      while (1) {
        QUEUE* q;
        uv_udp_send_t* req;

        if (pkt_num == len) {
          break;
        }

        if (QUEUE_EMPTY(&loop->netmap->write_queue)) {
          break;
        }

        q = QUEUE_HEAD(&loop->netmap->write_queue);
        req = QUEUE_DATA(q, uv_udp_send_t, queue);

        uv__udp_netmap_send_udp(loop, req, ring);
        uv__io_feed(loop, &loop->netmap->io_watcher);

        pkt_num++;
      }
    }
    uv__udp_netmap_run_completed(loop);
  }
}

int uv_udp_netmap_init(uv_loop_t* loop, const char* fname) {
  nm_desc_t* netmap_desc;

  if (loop->netmap != NULL) {
    return -1;
  }

  loop->netmap = uv__malloc(sizeof(uv_netmap_t));
  memset(loop->netmap, 0, sizeof(uv_netmap_t));

  netmap_desc = nm_open(fname, NULL, 0, 0);
  if (netmap_desc == NULL) {
    printf("netmap error\n");
    return -1;
  }

  loop->netmap->intf = netmap_desc;

  uv__handle_init(loop, (uv_handle_t*)loop->netmap, UV_NETMAP);
  uv__io_init(&loop->netmap->io_watcher, uv__udp_netmap_io, loop->netmap->intf->fd);
  QUEUE_INIT(&loop->netmap->write_queue);
  QUEUE_INIT(&loop->netmap->write_completed_queue);

  return 0;
}

int uv_udp_netmap_close(uv_loop_t* loop) {
  if (loop->netmap == NULL) {
    return 0;
  }

  // XXX consider doing an ioctl to force flush the ring

  loop->netmap->flags |= UV_HANDLE_CLOSING;
  loop->netmap->close_cb = (uv_close_cb)uv__free;
  uv__io_close(loop, &loop->netmap->io_watcher);
  uv__handle_stop(loop->netmap);

  loop->netmap->next_closing = loop->closing_handles;
  loop->closing_handles = (uv_handle_t*)loop->netmap;

  nm_close(loop->netmap->intf);

  return 0;
}

void uv_udp_netmap_set_network(uv_loop_t* loop, unsigned char* src_mac, unsigned char* dst_mac, unsigned char* src_ip) {
  if (loop->netmap == NULL) {
    return;
  }

  memcpy(loop->netmap->src_mac, src_mac, sizeof(loop->netmap->src_mac));
  memcpy(loop->netmap->dst_mac, dst_mac, sizeof(loop->netmap->dst_mac));
  memcpy(loop->netmap->src_ip, src_ip, sizeof(loop->netmap->src_ip));
}

void uv__udp_netmap_close_handle(uv_udp_t* handle) {
  if (handle->loop->netmap == NULL) {
    return;
  }

  if (handle->io_watcher.fd > 0) {
    handle->loop->netmap->sockets[handle->io_watcher.fd] = NULL;
    handle->loop->netmap->socket_tos[handle->io_watcher.fd] = 0;
  }

  handle->io_watcher.fd = -1;

  return;
}

void uv__udp_netmap_finish_close_handle(uv_udp_t* handle) {
  uv_udp_send_t* req;
  QUEUE* h;
  QUEUE* q;
  int removed;

  assert(handle->io_watcher.fd == -1);

  removed = 0;

  if (handle->loop->netmap != NULL) {
    if (!QUEUE_EMPTY(&handle->loop->netmap->write_queue)) {
      h = &handle->loop->netmap->write_queue;
      q = QUEUE_HEAD(h);
      while (q != h) {
        req = QUEUE_DATA(q, uv_udp_send_t, queue);
        if (req->handle == handle) {
          q = QUEUE_PREV(q);
          QUEUE_REMOVE(&req->queue);
          req->status = UV_ECANCELED;
          QUEUE_INSERT_TAIL(&handle->loop->netmap->write_completed_queue, &req->queue);
          removed = 1;
        }

        q = QUEUE_NEXT(q);
      }

      if (removed) {
        uv__udp_netmap_run_completed(handle->loop);
      }

      handle->recv_cb = NULL;
      handle->alloc_cb = NULL;
    }
  }
}


int uv__udp_netmap_bind(uv_udp_t* handle,
                        const struct sockaddr* addr,
                        unsigned int addrlen,
                        unsigned int flags) {
  const struct sockaddr_in* inaddr;
  uint16_t port;

  if (handle->loop->netmap == NULL) {
    return -1;
  }

  if (flags & UV_UDP_REUSEADDR) {
    assert(0 && "netmap-udp does not support binding with REUSEADDR");
    return -1;
  }

  if (addrlen != sizeof(struct sockaddr_in)) {
    assert(0 && "netmap-udp does not support binding ipv6 addresses");
    return -1;
  }
  inaddr = (const struct sockaddr_in*)addr;

  if (inaddr->sin_family != AF_INET) {
    assert(0 && "netmap-udp only suuports binding AF_INET addresses");
    return -1;
  }

  port = ntohs(inaddr->sin_port);

  if (port == 0) {
    assert(0 && "netmap-udp does not support binding port 0 (autobind)");
    return -1;
  }

  if (handle->loop->netmap->sockets[port] != NULL) {
    return -1;
  }

  handle->loop->netmap->sockets[port] = handle;
  handle->loop->netmap->socket_tos[port] = 0;
  handle->flags |= UV_HANDLE_BOUND;
  handle->io_watcher.fd = port;
  return 0;
}


int uv__udp_netmap_connect(uv_udp_t* handle,
                           const struct sockaddr* addr,
                           unsigned int addrlen) {
  if (handle->loop->netmap == NULL) {
    return -1;
  }

  assert(0 && "netmap-udp does not support connect()");
  return -1;
}


int uv__udp_netmap_disconnect(uv_udp_t* handle) {
  if (handle->loop->netmap == NULL) {
    return -1;
  }

  assert(0 && "netmap-udp does not support disconnect()");
  return -1;
}


int uv__udp_netmap_send(uv_udp_send_t* req,
                        uv_udp_t* handle,
                        const uv_buf_t bufs[],
                        unsigned int nbufs,
                        const struct sockaddr* addr,
                        unsigned int addrlen,
                        uv_udp_send_cb send_cb) {

  int enqueued;
  int i;

  if (handle->loop->netmap == NULL) {
    return -1;
  }

  uv__req_init(handle->loop, req, UV_UDP_SEND);
  QUEUE_INIT(&req->queue);
  memcpy(&req->addr, addr, addrlen);
  req->send_cb = send_cb;
  req->handle = handle;
  req->nbufs = nbufs;

  req->bufs = req->bufsml;
  if (nbufs > ARRAY_SIZE(req->bufsml)) {
    req->bufs = uv__malloc(nbufs * sizeof(bufs[0]));
  }

  memcpy(req->bufs, bufs, nbufs * sizeof(bufs[0]));

  enqueued = 0;

  // if we can, put this packet somewhere in a txring
  for (i = handle->loop->netmap->intf->first_rx_ring; i <= handle->loop->netmap->intf->last_rx_ring; i++) {
    struct netmap_ring* ring;
    int res;

    ring = NETMAP_TXRING(handle->loop->netmap->intf->nifp, i);

    res = uv__udp_netmap_send_udp(handle->loop, req, ring);
    if (res == 0) {
      enqueued = 1;
      break;
    }
  }

  // no space left, stash it locally
  if (!enqueued) {
    QUEUE_INSERT_TAIL(&handle->loop->netmap->write_queue, &req->queue);
  }

  // even if we put the packet in a ring, we still need to do a POLLOUT
  // POLLOUT signals that we want to send something
  uv__io_start(handle->loop, &handle->loop->netmap->io_watcher, POLLOUT);
  uv__handle_start(handle->loop->netmap);

  return 0;
}


int uv__udp_netmap_try_send(uv_udp_t* handle,
                            const uv_buf_t bufs[],
                            unsigned int nbufs,
                            const struct sockaddr* addr,
                            unsigned int addrlen) {
  if (handle->loop->netmap == NULL) {
    return -1;
  }

  assert(0 && "netmap-udp does not support try_send()");
  return -1;
}


int uv__udp_netmap_set_membership(uv_udp_t* handle,
                                  const char* multicast_addr,
                                  const char* interface_addr,
                                  uv_membership membership) {
  if (handle->loop->netmap == NULL) {
    return -1;
  }

  assert(0 && "netmap-udp does not support set_membership()");
  return -1;
}


int uv__udp_netmap_init_handle(uv_loop_t* loop, uv_udp_t* handle, unsigned int flags) {
  int domain;

  if (loop->netmap == NULL) {
    return -1;
  }

  domain = flags & 0xFF;
  if (domain != AF_INET && domain != AF_INET6 && domain != AF_UNSPEC) {
    return UV_EINVAL;
  }

  if (domain == AF_INET6) {
    assert(0 && "netmap-udp does not support ipv6");
    return -1;
  }

  if (domain != AF_UNSPEC) {
    assert(0 && "netmap-udp does not support auto binding");
    return -1;
  }

  uv__handle_init(loop, (uv_handle_t*)handle, UV_UDP);
  handle->alloc_cb = NULL;
  handle->recv_cb = NULL;
  handle->send_queue_size = 0;
  handle->send_queue_count = 0;
  handle->use_netmap = 1;
  QUEUE_INIT(&handle->write_queue);
  QUEUE_INIT(&handle->write_completed_queue);
  return 0;
}


int uv__udp_netmap_open(uv_udp_t* handle, uv_os_sock_t sock) {
  if (handle->loop->netmap == NULL) {
    return -1;
  }

  assert(0 && "netmap-udp does not support udp_open()");
  return -1;
}


int uv__udp_netmap_setsockopt(uv_udp_t* handle,
                              int option4,
                              int option6,
                              const void* val,
                              size_t size) {
  int intopt;

  if (handle->loop->netmap == NULL) {
    return -1;
  }

  if (handle->io_watcher.fd <= 0) {
    return -1;
  }

  if (option4 == IP_TOS) {
    if (size != sizeof(int)) {
      return -1;
    }
    intopt = *(int*)val;

    if (intopt > UCHAR_MAX) {
      return -1;
    }

    handle->loop->netmap->socket_tos[handle->io_watcher.fd] = (unsigned char)intopt;
    return 0;
  }

  assert(0 && "netmap-udp does not support given socket option");
  return -1;
}

int uv__udp_netmap_set_broadcast(uv_udp_t* handle, int on) {
  if (handle->loop->netmap == NULL) {
    return -1;
  }

  assert(0 && "netmap-udp does not support set_broadcast()");
  return -1;
}

int uv__udp_netmap_set_multicast_ttl(uv_udp_t* handle, int ttl) {
  if (handle->loop->netmap == NULL) {
    return -1;
  }

  assert(0 && "netmap-udp does not support set_multicast_ttl()");
  return -1;
}

int uv__udp_netmap_set_multicast_loop(uv_udp_t* handle, int on) {
  if (handle->loop->netmap == NULL) {
    return -1;
  }

  assert(0 && "netmap-udp does not support set_multicast_loop()");
  return -1;
}

int uv__udp_netmap_set_multicast_interface(uv_udp_t* handle, const char* interface_addr) {
  if (handle->loop->netmap == NULL) {
    return -1;
  }

  assert(0 && "netmap-udp does not support set_multicast_interface()");
  return -1;
}

int uv__udp_netmap_getpeername(const uv_udp_t* handle, struct sockaddr* name, int* namelen) {
  if (handle->loop->netmap == NULL) {
    return -1;
  }

  assert(0 && "netmap-udp does not support getpeername()");
  return -1;
}

int uv__udp_netmap_getsockname(const uv_udp_t* handle,
                               struct sockaddr* name,
                               int* namelen) {
  struct sockaddr_in* name_in;

  if (handle->loop->netmap == NULL) {
    return -1;
  }

  if (handle->io_watcher.fd <= 0) {
    return -1;
  }

  if (*namelen < 0) {
    return -1;
  }

  if ((unsigned int)*namelen < sizeof(struct sockaddr_in)) {
    return -1;
  }

  name_in = (struct sockaddr_in*)name;
  name_in->sin_family = AF_INET;
  name_in->sin_port = htons(handle->io_watcher.fd);
  memcpy(&name_in->sin_addr.s_addr, handle->loop->netmap->src_ip, sizeof(name_in->sin_addr.s_addr));
  *namelen = sizeof(struct sockaddr_in);
  return 0;
}


int uv__udp_netmap_recv_start(uv_udp_t* handle,
                              uv_alloc_cb alloc_cb,
                              uv_udp_recv_cb recv_cb) {
  if (handle->loop->netmap == NULL) {
    return -1;
  }
  handle->alloc_cb = alloc_cb;
  handle->recv_cb = recv_cb;

  if (!uv__io_active(&handle->loop->netmap->io_watcher, POLLIN)) {
    uv__io_start(handle->loop, &handle->loop->netmap->io_watcher, POLLIN);
    uv__handle_start((uv_handle_t*)handle->loop->netmap);
  }

  return 0;
}


int uv__udp_netmap_recv_stop(uv_udp_t* handle) {
  if (handle->loop->netmap == NULL) {
    return -1;
  }

  handle->alloc_cb = NULL;
  handle->recv_cb = NULL;

  return 0;
}
