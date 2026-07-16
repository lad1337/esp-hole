idf_component_register(SRCS "generator_main.c" "net.c" "fetch.c" "platform.c" "http_serve.c"
                             "artifact_store.c" "stats_ui.c" "allowlist.c"
                       INCLUDE_DIRS "."
                       PRIV_REQUIRES esp_driver_gpio esp_eth esp_netif esp_event
                                     nvs_flash esp_partition esp_http_server esp_http_client
                                     esp_timer mbedtls lwip blocklist_pipeline)
