// net.c — virtio-net driver + minimal IPv4 stack (ARP/ICMP/UDP-DNS/TCP client)
// for running epkg inside xv6 under QEMU slirp.
//
// Fixed guest config: QEMU user-network defaults:
//   ip 10.0.2.15/24, gateway (and host loopback) 10.0.2.2, dns 10.0.2.3.
// TCP is a simple client: in-order rx, single outstanding segment with
// retransmit, no congestion control. Enough for HTTP against a local mirror.

#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "defs.h"
#include "proc.h"
#include "virtio.h"

// mmio feature-select registers (modern virtio), absent from virtio.h
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL  0x014
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL  0x024

#define NETBASE_PROBE0 0x10001000UL
#define NSLOT          8             // virtio-mmio slots to probe
#define VNET_IRQ       2

#define QUEUE_RX 0
#define QUEUE_TX 1
#define QNUM     NUM                 // descriptors per queue (8, from virtio.h)

#define ETH_HLEN   14
#define ETH_P_IP   0x0800
#define ETH_P_ARP  0x0806
#define VNET_HDR   10                 // virtio_net_hdr (no mrg-rxbuf)
#define TXBUF_SZ   2048
#define RXBUF_SZ   2048
#define IPV4_TCP_H (ETH_HLEN + 20 + 20)

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

#define MSS        1400
#define RXRING     8192               // per-socket rx ring bytes
#define NSOCK      8
#define RTO_TICKS  5                   // 500ms retransmit
#define MAX_RETRY  20

enum sock_state { S_FREE, S_SYNSENT, S_ESTAB, S_FINSENT };

struct sock {
  enum sock_state state;
  uint16 lport, rport;
  uint32 rip;                        // ip in wire order
  uint32 rcv_nxt;                    // next expected seq
  uint32 snd_una;                    // oldest unacked seq
  uint32 snd_nxt;                    // next seq to send
  uint16 peer_wnd;
  char   rxbuf[RXRING];
  uint   rx_r, rx_w, rx_cnt;
  int    fin_rx;                     // peer sent FIN
  int    err;                        // reset / fatal timeout
  int    inflight;                   // tx slot in flight or -1
  uint32 infl_seq;                   // seq of in-flight segment
  int    infl_paylen;                // its tcp payload size (0 for SYN)
  int    retries;
  uint   sent_at;                    // ticks of last send
  int    deadline;                   // ticks for sleeper wakeup; 0 = none
};

static struct {
  uint64 base;                       // mmio base or 0
  struct spinlock lock;

  struct virtq_desc *rx_desc;
  struct virtq_avail *rx_avail;
  struct virtq_used *rx_used;
  uint16 rx_last;
  uint8 *rxbuf[QNUM];

  struct virtq_desc *tx_desc;
  struct virtq_avail *tx_avail;
  struct virtq_used *tx_used;
  uint16 tx_last;
  uint8 *txbuf[QNUM];
  int    txfree[QNUM];

  struct sock socks[NSOCK];
  uint16 next_port;

  struct { uint32 ip; uint8 mac[6]; } arp[4];
  int    arp_waiters;
  int    arp_deadline;

  int    dns_wait;
  uint16 dns_id;
  uint32 dns_result;                 // wire order
  int    dns_deadline;

  uint8  arpframe[TXBUF_SZ];         // shared scratch, only under net.lock
  uint8  tmpframe[TXBUF_SZ];
} net;

uint8 net_mac[6];

// wire-order ip constants, set in netinit
static uint32 our_ip, dns_ip;

#define R(r) ((volatile uint32 *)(net.base + (r)))

// ---------------- small helpers ----------------
static uint16
cksum_sum(const uint8 *p, int n, uint32 seed)
{
  uint32 sum = seed;
  while (n > 1) { sum += (p[0] << 8) | p[1]; p += 2; n -= 2; }
  if (n) sum += p[0] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (uint16)sum;
}

static uint16
cksum_fin(uint32 sum)
{
  return (uint16)~cksum_sum(0, 0, sum);
}

static void
put16(uint8 *p, uint16 v) { p[0] = (uint8)(v >> 8); p[1] = (uint8)v; }

static uint16
get16(const uint8 *p) { return (uint16)((p[0] << 8) | p[1]); }

static void
put32(uint8 *p, uint32 v)
{
  p[0] = (uint8)(v >> 24); p[1] = (uint8)(v >> 16);
  p[2] = (uint8)(v >> 8); p[3] = (uint8)v;
}

static uint32
get32(const uint8 *p)
{
  return ((uint32)p[0] << 24) | ((uint32)p[1] << 16) |
         ((uint32)p[2] << 8) | p[3];
}

// ---------------- tx slot management ----------------
static int
tx_alloc(void)
{
  for (int i = 0; i < QNUM; i++)
    if (net.txfree[i]) { net.txfree[i] = 0; return i; }
  return -1;
}

static void
tx_kick(int slot, int len)
{
  net.tx_desc[slot].addr = (uint64)net.txbuf[slot];
  net.tx_desc[slot].len  = len;
  net.tx_desc[slot].flags = 0;       // device-read
  net.tx_desc[slot].next = 0;
  net.tx_avail->ring[net.tx_avail->idx % QNUM] = slot;
  __sync_synchronize();
  net.tx_avail->idx++;
  __sync_synchronize();
  *R(VIRTIO_MMIO_QUEUE_NOTIFY) = QUEUE_TX;
}

// fire-and-forget frame (arp/icmp/dns), buf includes vnet header
static void
tx_frame(const uint8 *buf, int len)
{
  int s = tx_alloc();
  if (s < 0)
    return;                          // dropped; higher layers retransmit
  memmove(net.txbuf[s], buf, len);
  tx_kick(s, len);
}

// ---------------- ARP ----------------
static int
arp_lookup(uint32 ip, uint8 *mac)
{
  for (int i = 0; i < 4; i++)
    if (net.arp[i].ip == ip) {
      memmove(mac, net.arp[i].mac, 6);
      return 0;
    }
  return -1;
}

static void
arp_store(uint32 ip, const uint8 *mac)
{
  for (int i = 0; i < 4; i++)
    if (net.arp[i].ip == ip || net.arp[i].ip == 0) {
      net.arp[i].ip = ip;
      memmove(net.arp[i].mac, mac, 6);
      return;
    }
}

// build ethernet+arp frame into net.arpframe; returns length
static int
arp_build(uint16 op, uint32 tip, const uint8 *tmac)
{
  static const uint8 bcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
  uint8 *dst = net.arpframe;
  memset(dst, 0, VNET_HDR);
  memmove(dst + VNET_HDR, op == 1 ? bcast : tmac, 6);
  memmove(dst + VNET_HDR + 6, net_mac, 6);
  put16(dst + VNET_HDR + 12, ETH_P_ARP);
  uint8 *a = dst + VNET_HDR + ETH_HLEN;
  put16(a + 0, 1);                    // hw type: ethernet
  put16(a + 2, ETH_P_IP);
  a[4] = 6; a[5] = 4;
  put16(a + 6, op);
  memmove(a + 8, net_mac, 6);
  put32(a + 14, our_ip);
  if (tmac) memmove(a + 18, tmac, 6); else memset(a + 18, 0, 6);
  put32(a + 24, tip);
  return VNET_HDR + ETH_HLEN + 28;
}

// blocking: resolve ip to mac; net.lock held, released while sleeping
static int
arp_resolve(uint32 ip, uint8 *mac)
{
  if (arp_lookup(ip, mac) == 0)
    return 0;
  for (int attempt = 0; attempt < 3; attempt++) {
    int len = arp_build(1, ip, 0);
    tx_frame(net.arpframe, len);
    net.arp_waiters = 1;
    net.arp_deadline = ticks + 10;
    while (arp_lookup(ip, mac) != 0 && ticks < (uint)net.arp_deadline) {
      sleep_prepare(&net.arp_waiters);
      release(&net.lock);
      sleep();
      acquire(&net.lock);
    }
    if (arp_lookup(ip, mac) == 0)
      return 0;
  }
  return -1;
}

// ---------------- IP + TCP send ----------------
static void
ipv4_build(uint8 *ip, int tot_len, uint8 proto, uint32 dst)
{
  ip[0] = 0x45; ip[1] = 0;
  put16(ip + 2, tot_len);
  put16(ip + 4, 0);
  put16(ip + 6, 0x4000);              // DF
  ip[8] = 64; ip[9] = proto;
  put16(ip + 10, 0);                  // checksum field must be 0 while summing
  put32(ip + 12, our_ip);
  put32(ip + 16, dst);
  put16(ip + 10, cksum_fin(cksum_sum(ip, 20, 0)));
}

// send TCP segment from tx slot: slot buffer holds [vnet|eth|ip|tcp|data]
// seq, payload are copied here; caller set s->inflight bookkeeping
static int
tcp_send_seg(struct sock *s, uint8 flags, uint32 seq,
             const char *payload, int plen, int txslot)
{
  uint8 mac[6];
  if (txslot < 0)
    return -1;
  if (arp_resolve(s->rip, mac) != 0)
    return -1;

  uint8 *f = net.txbuf[txslot];
  uint8 *eth = f + VNET_HDR;
  memmove(eth, mac, 6);
  memmove(eth + 6, net_mac, 6);
  put16(eth + 12, ETH_P_IP);

  int iplen = 20, thlen = 20;
  uint8 *ip = eth + ETH_HLEN;
  ipv4_build(ip, iplen + thlen + plen, 6, s->rip);

  uint8 *th = ip + iplen;
  put16(th + 0, s->lport);
  put16(th + 2, s->rport);
  put32(th + 4, seq);
  put32(th + 8, s->rcv_nxt);
  th[12] = (uint8)(5 << 4); th[13] = flags;
  put16(th + 14, RXRING - s->rx_cnt);
  put16(th + 16, 0);                  // checksum filled below
  put16(th + 18, 0);
  if (plen) memmove(th + thlen, payload, plen);

  uint32 sum = 0;
  sum += cksum_sum(ip + 12, 8, 0);
  sum += 6;                           // proto word (0x0006 in BE16)
  sum += (uint16)(thlen + plen);
  sum += cksum_sum(th, thlen + plen, 0);
  put16(th + 16, cksum_fin(sum));

  tx_kick(txslot, VNET_HDR + IPV4_TCP_H + plen);
  return 0;
}

// ---------------- socket helpers ----------------
static struct sock *
sock_alloc(void)
{
  for (int i = 0; i < NSOCK; i++)
    if (net.socks[i].state == S_FREE)
      return &net.socks[i];
  return 0;
}

static void
sock_reset(struct sock *s)
{
  s->rx_r = s->rx_w = s->rx_cnt = 0;
  s->fin_rx = s->err = 0;
  s->inflight = -1;
  s->infl_paylen = 0;
  s->retries = 0;
  s->deadline = 0;
}

// ---------------- packet receive (net.lock held) ----------------
static void
arp_input(const uint8 *p, int len)
{
  if (len < 28) return;
  uint16 op = get16(p + 6);
  if (op == 1) {
    uint32 tip = get32(p + 24);
    if (tip == our_ip) {
      int n = arp_build(2, tip, p + 8);        // reply to sender
      tx_frame(net.arpframe, n);
    }
  } else if (op == 2) {
    uint32 sip = get32(p + 14);
    arp_store(sip, p + 8);
    wakeup(&net.arp_waiters);
  }
}

static int
rx_store(struct sock *s, const char *p, int n)
{
  int stored = 0;
  while (stored < n && s->rx_cnt < RXRING) {
    s->rxbuf[s->rx_w] = p[stored];
    s->rx_w = (s->rx_w + 1) % RXRING;
    s->rx_cnt++;
    stored++;
  }
  return stored;
}

static void
tcp_input(const uint8 *th, int tlen, uint32 sip)
{
  uint16 sport = get16(th + 0), dport = get16(th + 2);
  uint32 seq = get32(th + 4), ack = get32(th + 8);
  int doff = (th[12] >> 4) * 4;
  uint8 flags = th[13];
  int plen = tlen - doff;
  if (plen < 0) plen = 0;

  struct sock *s = 0;
  for (int i = 0; i < NSOCK; i++) {
    struct sock *t = &net.socks[i];
    if (t->state != S_FREE && t->rip == sip &&
        t->rport == sport && t->lport == dport) {
      s = t; break;
    }
  }
  if (!s) return;

  if (flags & TCP_RST) {
    s->err = 1;
    wakeup(s);
    return;
  }

  if (s->state == S_SYNSENT) {
    if ((flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) {
      s->rcv_nxt = seq + 1;
      s->snd_una = ack;
      s->snd_nxt = ack;
      s->peer_wnd = get16(th + 14) ? get16(th + 14) : 8192;
      s->state = S_ESTAB;
      // ACK the SYN: no slot bookkeeping (fire and forget)
      int slot = tx_alloc();
      if (slot >= 0)
        tcp_send_seg(s, TCP_ACK, s->snd_nxt, 0, 0, slot);
      wakeup(s);
    }
    return;
  }

  // S_ESTAB / S_FINSENT
  if (flags & TCP_ACK) {
    if ((int)(ack - s->snd_una) > 0) {
      s->snd_una = ack;
      if (s->inflight >= 0 && (int)(ack - (s->infl_seq + s->infl_paylen +
                                        (s->infl_paylen == 0 ? 1 : 0))) >= 0) {
        net.txfree[s->inflight] = 1;
        s->inflight = -1;
        s->retries = 0;
        wakeup(s);
      }
    }
    if (get16(th + 14))
      s->peer_wnd = get16(th + 14);
  }

  if (plen > 0) {
    if (seq == s->rcv_nxt) {
      int n = rx_store(s, (const char *)th + doff, plen);
      if (n > 0) {
        s->rcv_nxt += n;
        int slot = tx_alloc();
        if (slot >= 0)
          tcp_send_seg(s, TCP_ACK, s->snd_nxt, 0, 0, slot);
        wakeup(s);
      } else {
        // ring full: dup-ack carries the zero window back to the peer
        int slot = tx_alloc();
        if (slot >= 0)
          tcp_send_seg(s, TCP_ACK, s->snd_nxt, 0, 0, slot);
      }
    } else if ((int)(seq + plen - s->rcv_nxt) <= 0) {
      int slot = tx_alloc();               // old retransmit: re-ack
      if (slot >= 0)
        tcp_send_seg(s, TCP_ACK, s->snd_nxt, 0, 0, slot);
    }
    // future segment: dropped; our acks will trigger peer retransmit
  }

  if ((flags & TCP_FIN) && !s->fin_rx) {
    if (seq + plen == s->rcv_nxt) {
      s->rcv_nxt++;
      s->fin_rx = 1;
      int slot = tx_alloc();
      if (slot >= 0)
        tcp_send_seg(s, TCP_ACK, s->snd_nxt, 0, 0, slot);
      wakeup(s);
    }
  }
}

static void
icmp_input(const uint8 *icmp, int iplen, uint32 sip, const uint8 *ethmac)
{
  if (iplen < 8 || icmp[0] != 8) return;   // only echo request
  uint8 *f = net.tmpframe;
  memset(f, 0, VNET_HDR);
  uint8 *eth = f + VNET_HDR;
  memmove(eth, ethmac, 6);                 // reply straight to requester
  memmove(eth + 6, net_mac, 6);
  put16(eth + 12, ETH_P_IP);
  uint8 *o = eth + ETH_HLEN;
  ipv4_build(o, 20 + iplen, 1, sip);
  memmove(o + 20, icmp, iplen);
  o[20] = 0;                               // echo reply
  put16(o + 22, 0);
  put16(o + 22, cksum_fin(cksum_sum(o + 20, iplen, 0)));
  tx_frame(f, VNET_HDR + ETH_HLEN + 20 + iplen);
}

static void
udp_input(const uint8 *uh, int ulen)
{
  if (ulen < 20 || !net.dns_wait) return;  // 8 udp + 12 dns hdr
  if (get16(uh + 2) != 53) return;
  const uint8 *d = uh + 8;
  uint16 id = get16(d + 0);
  if (id != net.dns_id) return;
  uint16 flags = get16(d + 2), an = get16(d + 6);
  if ((flags & 0x8000) == 0) return;       // not a response
  if ((flags & 0x000f) != 0 || an == 0) {
    net.dns_result = 0;
    net.dns_wait = 0;
    wakeup(&net.dns_wait);
    return;
  }
  uint16 qd = get16(d + 4);
  const uint8 *p = d + 12;
  const uint8 *end = uh + ulen;
  for (uint16 i = 0; i < qd && p < end; i++) {
    while (p < end && *p) {
      if (*p & 0xc0) { p += 2; goto qdone; }
      p += *p + 1;
    }
    p += 5;
  }
qdone:
  for (uint16 i = 0; i < an && p + 12 <= end; i++) {
    while (p < end && *p) {
      if (*p & 0xc0) { p += 2; break; }
      p += *p + 1;
    }
    uint16 type = get16(p);
    uint16 rdlen = get16(p + 8);
    p += 10;
    if (p + rdlen > end) break;
    if (type == 1 && rdlen == 4) {
      net.dns_result = get32(p);
      break;
    }
    p += rdlen;
  }
  net.dns_wait = 0;
  wakeup(&net.dns_wait);
}

static void
ipv4_input(const uint8 *p, int len, const uint8 *ethmac)
{
  if (len < 20 || (p[0] >> 4) != 4) return;
  int ihl = (p[0] & 0xf) * 4;
  if (ihl < 20 || len < ihl) return;
  uint32 dst = get32(p + 16);
  if (dst != our_ip) return;
  uint32 sip = get32(p + 12);
  int tot = get16(p + 2);
  if (tot > len) tot = len;
  uint8 proto = p[9];
  if (proto == 1)
    icmp_input(p + ihl, tot - ihl, sip, ethmac);
  else if (proto == 6)
    tcp_input(p + ihl, tot - ihl, sip);
  else if (proto == 17)
    udp_input(p + ihl, tot - ihl);
}

static void
eth_input(uint8 *p, int len)
{
  if (len < ETH_HLEN) return;
  uint16 et = get16(p + 12);
  if (et == ETH_P_ARP)
    arp_input(p + ETH_HLEN, len - ETH_HLEN);
  else if (et == ETH_P_IP)
    ipv4_input(p + ETH_HLEN, len - ETH_HLEN, p + 6);
}

// ---------------- device ----------------
static uint64
vnet_probe(void)
{
  for (int i = 0; i < NSLOT; i++) {
    volatile uint32 *b = (volatile uint32 *)(NETBASE_PROBE0 + i * 0x1000);
    if (b[0] != 0x74726976) continue;      // magic "virt"
    if (b[1] != 2) continue;               // modern mmio
    if (b[2] == 1) return NETBASE_PROBE0 + i * 0x1000;  // net device id
  }
  return 0;
}

static void
vnet_queue_init(int qsel, struct virtq_desc **d,
                struct virtq_avail **a, struct virtq_used **u)
{
  *R(VIRTIO_MMIO_QUEUE_SEL) = qsel;
  if (*R(VIRTIO_MMIO_QUEUE_READY))
    panic("vnet queue ready");
  if (*R(VIRTIO_MMIO_QUEUE_NUM_MAX) < QNUM)
    panic("vnet queue small");
  *R(VIRTIO_MMIO_QUEUE_NUM) = QNUM;
  *d = kalloc(); *a = kalloc(); *u = kalloc();
  if (!*d || !*a || !*u)
    panic("vnet kalloc");
  memset(*d, 0, PGSIZE);
  memset(*a, 0, PGSIZE);
  memset(*u, 0, PGSIZE);
  *R(VIRTIO_MMIO_QUEUE_DESC_LOW) = (uint64)*d;
  *R(VIRTIO_MMIO_QUEUE_DESC_HIGH) = (uint64)*d >> 32;
  *R(VIRTIO_MMIO_DRIVER_DESC_LOW) = (uint64)*a;
  *R(VIRTIO_MMIO_DRIVER_DESC_HIGH) = (uint64)*a >> 32;
  *R(VIRTIO_MMIO_DEVICE_DESC_LOW) = (uint64)*u;
  *R(VIRTIO_MMIO_DEVICE_DESC_HIGH) = (uint64)*u >> 32;
  *R(VIRTIO_MMIO_QUEUE_READY) = 1;
}

void
netinit(void)
{
  initlock(&net.lock, "net");
  for (int i = 0; i < NSOCK; i++) {
    net.socks[i].state = S_FREE;
    net.socks[i].inflight = -1;
  }
  for (int i = 0; i < QNUM; i++) net.txfree[i] = 1;
  net.next_port = 32768;

  net.base = vnet_probe();
  if (!net.base) {
    printk("net: no virtio-net device found\n");
    return;
  }

  uint32 status = 0;
  *R(VIRTIO_MMIO_STATUS) = status;
  status |= VIRTIO_CONFIG_S_ACKNOWLEDGE;
  *R(VIRTIO_MMIO_STATUS) = status;
  status |= VIRTIO_CONFIG_S_DRIVER;
  *R(VIRTIO_MMIO_STATUS) = status;

  // negotiate: only VIRTIO_NET_F_MAC
  *R(VIRTIO_MMIO_DEVICE_FEATURES_SEL) = 0;
  *R(VIRTIO_MMIO_DRIVER_FEATURES_SEL) = 0;
  *R(VIRTIO_MMIO_DRIVER_FEATURES) = 1u << 5;
  status |= VIRTIO_CONFIG_S_FEATURES_OK;
  *R(VIRTIO_MMIO_STATUS) = status;
  status = *R(VIRTIO_MMIO_STATUS);
  if (!(status & VIRTIO_CONFIG_S_FEATURES_OK))
    panic("vnet FEATURES_OK");

  vnet_queue_init(QUEUE_RX, &net.rx_desc, &net.rx_avail, &net.rx_used);
  vnet_queue_init(QUEUE_TX, &net.tx_desc, &net.tx_avail, &net.tx_used);

  for (int i = 0; i < 6; i++)
    net_mac[i] = *((volatile uint8 *)net.base + 0x100 + i);

  status |= VIRTIO_CONFIG_S_DRIVER_OK;
  *R(VIRTIO_MMIO_STATUS) = status;

  // pre-post rx buffers and tx buffers, two per page
  uint8 *pg = 0;
  for (int i = 0; i < QNUM; i++) {
    if (i % 2 == 0) {
      pg = kalloc();
      if (!pg) panic("vnet rxbuf");
    }
    net.rxbuf[i] = pg + (i % 2) * RXBUF_SZ;
    net.rx_desc[i].addr = (uint64)net.rxbuf[i];
    net.rx_desc[i].len = RXBUF_SZ;
    net.rx_desc[i].flags = 2;              // device-write
    net.rx_desc[i].next = 0;
    net.rx_avail->ring[i] = i;
  }
  net.rx_avail->idx = QNUM;
  __sync_synchronize();
  *R(VIRTIO_MMIO_QUEUE_NOTIFY) = QUEUE_RX;

  pg = 0;
  for (int i = 0; i < QNUM; i++) {
    if (i % 2 == 0) {
      pg = kalloc();
      if (!pg) panic("vnet txbuf");
    }
    net.txbuf[i] = pg + (i % 2) * TXBUF_SZ;
  }

  our_ip = 0x0A00020F;                     // 10.0.2.15 (BE wire order)
  dns_ip = 0x0A000203;                     // 10.0.2.3

  printk("net: virtio-net at %p mac %x:%x:%x:%x:%x:%x\n",
         (void *)net.base, net_mac[0], net_mac[1], net_mac[2],
         net_mac[3], net_mac[4], net_mac[5]);
}

void
virtio_net_intr(void)
{
  acquire(&net.lock);
  uint32 st = *R(VIRTIO_MMIO_INTERRUPT_STATUS);
  *R(VIRTIO_MMIO_INTERRUPT_ACK) = st;

  while (net.rx_last != net.rx_used->idx) {
    struct virtq_used_elem *e = &net.rx_used->ring[net.rx_last % QNUM];
    net.rx_last++;
    int n = e->len;
    int di = e->id;
    if (n > VNET_HDR + ETH_HLEN)
      eth_input(net.rxbuf[di] + VNET_HDR, n - VNET_HDR);
    net.rx_desc[di].len = RXBUF_SZ;
    net.rx_avail->ring[net.rx_avail->idx % QNUM] = di;
    net.rx_avail->idx++;
    __sync_synchronize();
    *R(VIRTIO_MMIO_QUEUE_NOTIFY) = QUEUE_RX;
  }

  while (net.tx_last != net.tx_used->idx) {
    struct virtq_used_elem *e = &net.tx_used->ring[net.tx_last % QNUM];
    net.tx_last++;
    int di = e->id;
    int keep = 0;
    for (int i = 0; i < NSOCK; i++)
      if (net.socks[i].inflight == di && net.socks[i].state != S_FREE)
        keep = 1;                          // freed on TCP ack/timeout
    if (!keep)
      net.txfree[di] = 1;
    wakeup(&net.txfree[0]);
  }

  release(&net.lock);
}

// every tick (100ms), from clockintr
void
net_tick(void)
{
  if (!net.base) return;
  acquire(&net.lock);
  for (int i = 0; i < NSOCK; i++) {
    struct sock *s = &net.socks[i];
    if (s->state == S_FREE) continue;
    if (s->inflight >= 0 && ticks - s->sent_at >= RTO_TICKS) {
      if (s->retries > MAX_RETRY) {
        s->err = 1;
        net.txfree[s->inflight] = 1;
        s->inflight = -1;
        wakeup(s);
      } else {
        tx_kick(s->inflight, VNET_HDR + IPV4_TCP_H + s->infl_paylen);
        s->sent_at = ticks;
        s->retries++;
      }
    }
    if (s->deadline && (int)ticks >= s->deadline) {
      s->deadline = 0;
      wakeup(s);
    }
  }
  if (net.arp_waiters && net.arp_deadline && (int)ticks >= net.arp_deadline) {
    net.arp_deadline = 0;
    wakeup(&net.arp_waiters);
  }
  if (net.dns_wait && net.dns_deadline && (int)ticks >= net.dns_deadline) {
    net.dns_deadline = 0;
    net.dns_wait = 0;
    net.dns_result = 0;
    wakeup(&net.dns_wait);
  }
  release(&net.lock);
}

// ---------------- syscalls ----------------

// resolve DNS name to ip (wire order u32); 0 on failure
uint64
sys_netresolve(void)
{
  char name[128];
  if (argstr(0, name, sizeof(name)) < 0) return 0;
  if (!net.base) return 0;

  acquire(&net.lock);
  int nl = 0;
  while (name[nl] && nl < 120) nl++;

  uint8 *q = net.tmpframe + VNET_HDR + ETH_HLEN + 20 + 8;
  int qlen = 0;
  uint16 id = (uint16)(ticks * 7 + net.next_port);
  net.dns_id = id;
  q[qlen++] = (uint8)(id >> 8); q[qlen++] = (uint8)id;
  q[qlen++] = 0x01; q[qlen++] = 0x00;      // RD
  q[qlen++] = 0; q[qlen++] = 1;            // qdcount
  q[qlen++] = 0; q[qlen++] = 0;            // ancount
  q[qlen++] = 0; q[qlen++] = 0;            // nscount
  q[qlen++] = 0; q[qlen++] = 0;            // arcount
  int i = 0;
  while (i < nl) {
    int lab = 0;
    while (i + lab < nl && name[i + lab] != '.') lab++;
    q[qlen++] = (uint8)lab;
    memmove(q + qlen, name + i, lab);
    qlen += lab;
    i += lab;
    if (name[i] == '.') i++;
  }
  q[qlen++] = 0;
  q[qlen++] = 0; q[qlen++] = 1;            // type A
  q[qlen++] = 0; q[qlen++] = 1;            // class IN

  uint8 mac[6];
  if (arp_resolve(dns_ip, mac) != 0) {
    release(&net.lock);
    return 0;
  }
  uint8 *f = net.tmpframe;
  memset(f, 0, VNET_HDR);
  uint8 *eth = f + VNET_HDR;
  memmove(eth, mac, 6);
  memmove(eth + 6, net_mac, 6);
  put16(eth + 12, ETH_P_IP);
  uint8 *ip = eth + ETH_HLEN;
  ipv4_build(ip, 20 + 8 + qlen, 17, dns_ip);
  uint8 *uh = ip + 20;
  put16(uh + 0, net.next_port++);
  if (net.next_port == 0) net.next_port = 32768;
  put16(uh + 2, 53);
  put16(uh + 4, 8 + qlen);
  put16(uh + 6, 0);

  net.dns_wait = 1;
  net.dns_result = 0;
  tx_frame(f, VNET_HDR + ETH_HLEN + 20 + 8 + qlen);
  net.dns_deadline = ticks + 50;           // 5s
  while (net.dns_wait && (int)ticks < net.dns_deadline) {
    sleep_prepare(&net.dns_wait);
    release(&net.lock);
    sleep();
    acquire(&net.lock);
  }
  uint32 r = net.dns_result;
  release(&net.lock);
  return r;
}

// connect(ip_wire_u32, port); returns socket index or -1
uint64
sys_netconnect(void)
{
  int ip, port;
  argint(0, &ip);
  argint(1, &port);
  if (!net.base || port <= 0 || port > 65535) return -1;

  acquire(&net.lock);
  struct sock *s = sock_alloc();
  if (!s) { release(&net.lock); return -1; }
  sock_reset(s);
  s->rip = (uint32)ip;
  s->rport = (uint16)port;
  s->lport = net.next_port++;
  if (net.next_port == 0) net.next_port = 32768;
  s->snd_nxt = s->snd_una = (uint32)ticks * 1000 + s->lport;
  s->state = S_SYNSENT;
  int slot = tx_alloc();
  if (slot < 0) { s->state = S_FREE; release(&net.lock); return -1; }
  s->inflight = slot;
  s->infl_seq = s->snd_nxt;
  s->infl_paylen = 0;
  s->retries = 0;
  if (tcp_send_seg(s, TCP_SYN, s->snd_nxt, 0, 0, slot) != 0) {
    net.txfree[slot] = 1;
    s->inflight = -1;
    s->state = S_FREE;
    release(&net.lock);
    return -1;
  }
  s->snd_nxt++;
  s->sent_at = ticks;
  int deadline = ticks + 150;              // 15s
  s->deadline = deadline;
  while (s->state == S_SYNSENT && !s->err && (int)ticks < deadline) {
    sleep_prepare(s);
    release(&net.lock);
    sleep();
    acquire(&net.lock);
  }
  s->deadline = 0;
  int ok = (s->state == S_ESTAB && !s->err);
  if (!ok) {
    if (s->inflight >= 0) { net.txfree[s->inflight] = 1; s->inflight = -1; }
    s->state = S_FREE;
    release(&net.lock);
    return -1;
  }
  release(&net.lock);
  return (uint64)(s - net.socks);
}

// netwrite(fd, buf, n): send up to MSS bytes, block until acked
uint64
sys_netwrite(void)
{
  int fd, n;
  uint64 uaddr;
  struct proc *p = myproc();
  argint(0, &fd);
  argaddr(1, &uaddr);
  argint(2, &n);
  if (fd < 0 || fd >= NSOCK || n <= 0) return -1;

  acquire(&net.lock);
  struct sock *s = &net.socks[fd];
  if (s->state != S_ESTAB || s->err) { release(&net.lock); return -1; }
  int cnt = n;
  if (cnt > MSS) cnt = MSS;
  if (cnt > (int)s->peer_wnd) cnt = (int)s->peer_wnd;
  if (cnt <= 0) { release(&net.lock); return -1; }

  int slot = tx_alloc();
  if (slot < 0) { release(&net.lock); return -1; }
  char kbuf[MSS];
  release(&net.lock);
  if (copyin(p->pagetable, p->sz, kbuf, uaddr, cnt) != 0) {
    acquire(&net.lock);
    net.txfree[slot] = 1;
    release(&net.lock);
    return -1;
  }
  acquire(&net.lock);
  if (s->state != S_ESTAB || s->err) {
    net.txfree[slot] = 1;
    release(&net.lock);
    return -1;
  }
  uint32 seq = s->snd_nxt;
  s->inflight = slot;
  s->infl_seq = seq;
  s->infl_paylen = cnt;
  s->retries = 0;
  if (tcp_send_seg(s, TCP_ACK | TCP_PSH, seq, kbuf, cnt, slot) != 0) {
    net.txfree[slot] = 1;
    s->inflight = -1;
    s->err = 1;
    release(&net.lock);
    return -1;
  }
  s->snd_nxt = seq + cnt;
  s->sent_at = ticks;
  int deadline = ticks + 100;              // 10s
  s->deadline = deadline;
  while (s->inflight == slot && !s->err && (int)ticks < deadline) {
    sleep_prepare(s);
    release(&net.lock);
    sleep();
    acquire(&net.lock);
  }
  s->deadline = 0;
  int ok = (s->inflight != slot && !s->err);
  if (s->inflight == slot) {
    net.txfree[slot] = 1;
    s->inflight = -1;
  }
  release(&net.lock);
  return ok ? cnt : -1;
}

// netread(fd, buf, n): >0 data, 0 clean eof, -1 error/timeout
uint64
sys_netread(void)
{
  int fd, n;
  uint64 uaddr;
  struct proc *p = myproc();
  argint(0, &fd);
  argaddr(1, &uaddr);
  argint(2, &n);
  if (fd < 0 || fd >= NSOCK || n <= 0) return -1;

  acquire(&net.lock);
  struct sock *s = &net.socks[fd];
  if (s->state == S_FREE) { release(&net.lock); return -1; }
  int deadline = ticks + 300;              // 30s
  s->deadline = deadline;
  while (s->rx_cnt == 0 && !s->fin_rx && !s->err && s->state != S_FREE &&
         (int)ticks < deadline) {
    sleep_prepare(s);
    release(&net.lock);
    sleep();
    acquire(&net.lock);
  }
  s->deadline = 0;
  if (s->rx_cnt == 0) {
    int r = s->err ? -1 : 0;
    if (s->state == S_FREE) r = -1;
    release(&net.lock);
    return r;
  }
  int cnt = s->rx_cnt;
  if (cnt > n) cnt = n;
  if (cnt > 1400) cnt = 1400;
  char kbuf[1400];
  int stored = 0;
  for (int i = 0; i < cnt; i++) {
    kbuf[i] = s->rxbuf[s->rx_r];
    s->rx_r = (s->rx_r + 1) % RXRING;
    s->rx_cnt--;
    stored++;
  }
  release(&net.lock);
  if (copyout(p->pagetable, p->sz, uaddr, kbuf, stored) != 0)
    return -1;
  return stored;
}

uint64
sys_netclose(void)
{
  int fd;
  argint(0, &fd);
  if (fd < 0 || fd >= NSOCK) return -1;
  acquire(&net.lock);
  struct sock *s = &net.socks[fd];
  if (s->state == S_FREE) { release(&net.lock); return -1; }
  if (s->state == S_ESTAB && !s->err) {
    int slot = tx_alloc();
    if (slot >= 0) {
      tcp_send_seg(s, TCP_ACK | TCP_FIN, s->snd_nxt, 0, 0, slot);
      s->snd_nxt++;
      // slot is freed by the device-completion irq (no sock references it)
    }
  }
  if (s->inflight >= 0) net.txfree[s->inflight] = 1;
  s->state = S_FREE;
  s->inflight = -1;
  wakeup(s);
  release(&net.lock);
  return 0;
}
