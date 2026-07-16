/* net.c — see net.h. Ported from main/dns_sinkhole.c's eth_start()/
 * on_got_ip(); DNS-agnostic, so it carries over unchanged in spirit. */
#include "net.h"

#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "esp_eth.h"
#include "esp_eth_netif_glue.h"
#include "esp_eth_phy_ip101.h" /* onboard PHY on the ESP32-P4-Function-EV-Board */
#include "esp_event.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_netif.h"

static const char *TAG = "net";

static EventGroupHandle_t s_net_events;
#define GOT_IP_BIT BIT0
static char s_node_ip[16]; /* dotted-quad, filled in on_got_ip() */

static void on_got_ip(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    const ip_event_got_ip_t *event = data;
    ESP_LOGI(TAG, "got IP " IPSTR, IP2STR(&event->ip_info.ip));
    snprintf(s_node_ip, sizeof(s_node_ip), IPSTR, IP2STR(&event->ip_info.ip));
    xEventGroupSetBits(s_net_events, GOT_IP_BIT);
}

void net_start(void)
{
    s_net_events = xEventGroupCreate();
    configASSERT(s_net_events != NULL);

#if CONFIG_GENERATOR_ETH_PHY_POWER_GPIO >= 0
    /* Some boards gate the PHY power / 50 MHz oscillator behind a GPIO. */
    const gpio_config_t power_pin = {
        .pin_bit_mask = 1ULL << CONFIG_GENERATOR_ETH_PHY_POWER_GPIO,
        .mode = GPIO_MODE_OUTPUT,
    };
    ESP_ERROR_CHECK(gpio_config(&power_pin));
    gpio_set_level(CONFIG_GENERATOR_ETH_PHY_POWER_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(50)); /* let the PHY/oscillator settle */
#endif

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    const esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *eth_netif = esp_netif_new(&netif_cfg);

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_esp32_emac_config_t emac_config = ETH_ESP32_EMAC_DEFAULT_CONFIG();
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 3, 0)
    emac_config.smi_gpio.mdc_num = CONFIG_GENERATOR_ETH_MDC_GPIO;
    emac_config.smi_gpio.mdio_num = CONFIG_GENERATOR_ETH_MDIO_GPIO;
#else
    emac_config.smi_mdc_gpio_num = CONFIG_GENERATOR_ETH_MDC_GPIO;
    emac_config.smi_mdio_gpio_num = CONFIG_GENERATOR_ETH_MDIO_GPIO;
#endif
    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&emac_config, &mac_config);

    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.phy_addr = CONFIG_GENERATOR_ETH_PHY_ADDR;
    phy_config.reset_gpio_num = CONFIG_GENERATOR_ETH_PHY_RST_GPIO;
    esp_eth_phy_t *phy = esp_eth_phy_new_ip101(&phy_config);

    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth_handle = NULL;
    ESP_ERROR_CHECK(esp_eth_driver_install(&eth_config, &eth_handle));
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif,
                                     esp_eth_new_netif_glue(eth_handle)));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP,
                                               on_got_ip, NULL));
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));
}

void net_wait_for_ip(void)
{
    xEventGroupWaitBits(s_net_events, GOT_IP_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
}

const char *net_node_ip(void)
{
    return s_node_ip;
}
