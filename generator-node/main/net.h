/* net.h — Ethernet bring-up for the generator node. Ported from
 * main/dns_sinkhole.c's eth_start()/on_got_ip(): same RMII/IP101 bring-up,
 * no DNS-specific logic. This project is ESP32-P4-only, so unlike the
 * sinkhole firmware there's no target branching for the PHY driver.
 */
#pragma once

/* Starts the netif/event loop/Ethernet driver. Call once from app_main(). */
void net_start(void);

/* Blocks until DHCP has assigned an address. */
void net_wait_for_ip(void);

/* Dotted-quad IPv4 address, valid only after net_wait_for_ip() returns. */
const char *net_node_ip(void);
