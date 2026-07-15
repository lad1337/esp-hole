idf_component_register(SRCS "dns_sinkhole.c" "blocklist.c" "updater.c" "stats.c"
                       INCLUDE_DIRS "."
                       PRIV_REQUIRES esp_driver_gpio esp_eth esp_netif esp_event lwip
                                     nvs_flash esp_partition esp_http_client
                                     mbedtls esp_timer)
