#include "reCerts.h"
#include "rLog.h"
#include "project_config.h"
#include "def_consts.h"

#if CONFIG_TELEGRAM_ENABLE && defined(CONFIG_TELEGRAM_TLS_PEM_STORAGE) && (CONFIG_TELEGRAM_TLS_PEM_STORAGE == TLS_CERT_GLOBAL)
  #define _TLS_TELEGRAM_GLOBAL 1
#else
  #define _TLS_TELEGRAM_GLOBAL 0
#endif // CONFIG_TELEGRAM_TLS_PEM_STORAGE

#if CONFIG_OPENMON_ENABLE && defined(CONFIG_OPENMON_TLS_PEM_STORAGE) && (CONFIG_OPENMON_TLS_PEM_STORAGE == TLS_CERT_GLOBAL)
  #define _TLS_OPENMON_GLOBAL 1
#else
  #define _TLS_OPENMON_GLOBAL 0
#endif // CONFIG_OPENMON_TLS_PEM_STORAGE

#if CONFIG_NARODMON_ENABLE && defined(CONFIG_NARODMON_TLS_PEM_STORAGE) && (CONFIG_NARODMON_TLS_PEM_STORAGE == TLS_CERT_GLOBAL)
  #define _TLS_NARODMON_GLOBAL 1
#else
  #define _TLS_NARODMON_GLOBAL 0
#endif // CONFIG_NARODMON_TLS_PEM_STORAGE

#if CONFIG_THINGSPEAK_ENABLE && defined(CONFIG_THINGSPEAK_TLS_PEM_STORAGE) && (CONFIG_THINGSPEAK_TLS_PEM_STORAGE == TLS_CERT_GLOBAL)
  #define _TLS_THINGSPEAK_GLOBAL 1
#else
  #define _TLS_THINGSPEAK_GLOBAL 0
#endif // CONFIG_THINGSPEAK_TLS_PEM_STORAGE

#if CONFIG_MQTT_OTA_ENABLE && defined(CONFIG_OTA_PEM_STORAGE) && (CONFIG_OTA_PEM_STORAGE == TLS_CERT_GLOBAL)
  #define _TLS_OTA_GLOBAL 1
#else
  #define _TLS_OTA_GLOBAL 0
#endif // CONFIG_OTA_PEM_STORAGE

#if defined(CONFIG_MQTT1_TYPE) && defined(CONFIG_MQTT1_TLS_ENABLED) && defined(CONFIG_MQTT1_TLS_STORAGE) && (CONFIG_MQTT1_TLS_STORAGE == TLS_CERT_GLOBAL)
  #define _TLS_MQTT1_GLOBAL 1
#else
  #define _TLS_MQTT1_GLOBAL 0
#endif // CONFIG_MQTT1_TLS_STORAGE

#if defined(CONFIG_MQTT2_TYPE) && defined(CONFIG_MQTT2_TLS_ENABLED) && defined(CONFIG_MQTT2_TLS_STORAGE) && (CONFIG_MQTT2_TLS_STORAGE == TLS_CERT_GLOBAL)
  #define _TLS_MQTT2_GLOBAL 1
#else
  #define _TLS_MQTT2_GLOBAL 0
#endif // CONFIG_MQTT2_TLS_STORAGE

#if _TLS_TELEGRAM_GLOBAL || _TLS_OPENMON_GLOBAL || _TLS_NARODMON_GLOBAL || _TLS_THINGSPEAK_GLOBAL || _TLS_OTA_GLOBAL || _TLS_MQTT1_GLOBAL || _TLS_MQTT2_GLOBAL
  #include "esp_tls.h"
  #define _TLS_GLOBAL_ENABLED 1
#else
  #define _TLS_GLOBAL_ENABLED 0
#endif 

#if _TLS_GLOBAL_ENABLED
  static const char* logTAG = "GCAS";

  // Root certificate for most sites
  extern const char default_pem_start[]             asm(CONFIG_DEFAULT_TLS_PEM_START);
  extern const char default_pem_end[]               asm(CONFIG_DEFAULT_TLS_PEM_END); 

  #if _TLS_TELEGRAM_GLOBAL && defined(CONFIG_TELEGRAM_TLS_PEM_START)
    extern const char api_telegram_org_pem_start[]  asm(CONFIG_TELEGRAM_TLS_PEM_START);
    extern const char api_telegram_org_pem_end[]    asm(CONFIG_TELEGRAM_TLS_PEM_END); 
  #endif // _TLS_TELEGRAM_GLOBAL

  #if _TLS_OPENMON_GLOBAL && defined(CONFIG_OPENMON_TLS_PEM_START)
    extern const char api_openmon_ru_pem_start[]    asm(CONFIG_OPENMON_TLS_PEM_START);
    extern const char api_openmon_ru_pem_end[]      asm(CONFIG_OPENMON_TLS_PEM_END); 
  #endif // _TLS_OPENMON_GLOBAL

  #if _TLS_NARODMON_GLOBAL && defined(CONFIG_NARODMON_TLS_PEM_START)
    extern const char api_narodmon_ru_pem_start[]   asm(CONFIG_NARODMON_TLS_PEM_START);
    extern const char api_narodmon_ru_pem_end[]     asm(CONFIG_NARODMON_TLS_PEM_END); 
  #endif // _TLS_NARODMON_GLOBAL

  #if _TLS_THINGSPEAK_GLOBAL && defined(CONFIG_THINGSPEAK_TLS_PEM_START)
    extern const char api_thingspeak_pem_start[]    asm(CONFIG_THINGSPEAK_TLS_PEM_START);
    extern const char api_thingspeak_pem_end[]      asm(CONFIG_THINGSPEAK_TLS_PEM_END); 
  #endif // _TLS_THINGSPEAK_GLOBAL

  #if _TLS_OTA_GLOBAL && defined(CONFIG_OTA_PEM_START)
    extern const char ota_pem_start[]            asm(CONFIG_OTA_PEM_START);
    extern const char ota_pem_end[]              asm(CONFIG_OTA_PEM_END); 
  #endif // CONFIG_MQTT_OTA_ENABLE

  #if _TLS_MQTT1_GLOBAL && defined(CONFIG_MQTT1_TLS_PEM_START)
    extern const char mqtt1_pem_start[]          asm(CONFIG_MQTT1_TLS_PEM_START);
    extern const char mqtt1_pem_end[]            asm(CONFIG_MQTT1_TLS_PEM_END); 
  #endif // CONFIG_MQTT1_TYPE

  #if _TLS_MQTT2_GLOBAL && defined(CONFIG_MQTT2_TLS_PEM_START)
    extern const char mqtt2_pem_start[]          asm(CONFIG_MQTT2_TLS_PEM_START);
    extern const char mqtt2_pem_end[]            asm(CONFIG_MQTT2_TLS_PEM_END); 
  #endif // CONFIG_MQTT2_TYPE
#endif // _TLS_GLOBAL_ENABLED

bool initTlsGlobalCAStore()
{
  // CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
  #if _TLS_GLOBAL_ENABLED
    // Set certificates into global store
    esp_err_t err = esp_tls_init_global_ca_store();
    if (err != ESP_OK) {
      rlog_e(logTAG, "Failed to init global CA store");
      return false;
    };
    vTaskDelay(1);
    
    rlog_i(logTAG, "Load certificate for ISRG X1 (default root)");
    err = esp_tls_set_global_ca_store((const unsigned char*)default_pem_start, default_pem_end-default_pem_start);
    if (err != ESP_OK) {
      rlog_e(logTAG, "Failed to load certificate for ISRG X1");
      return false;
    };
    vTaskDelay(1);

    #if _TLS_TELEGRAM_GLOBAL && defined(CONFIG_TELEGRAM_TLS_PEM_START)
      if (api_telegram_org_pem_start != default_pem_start) {
        rlog_i(logTAG, "Load certificate for Telegram API");
        err = esp_tls_set_global_ca_store((const unsigned char*)api_telegram_org_pem_start, api_telegram_org_pem_end-api_telegram_org_pem_start);
        if (err != ESP_OK) {
          rlog_e(logTAG, "Failed to load certificate for Telegram API");
          return false;
        };
      };
      vTaskDelay(1);
    #endif // _TLS_TELEGRAM_GLOBAL

    #if _TLS_OPENMON_GLOBAL && defined(CONFIG_OPENMON_TLS_PEM_START)
      if (api_openmon_ru_pem_start != default_pem_start) {
        rlog_i(logTAG, "Load certificate for OpenMon API");
        err = esp_tls_set_global_ca_store((const unsigned char*)api_openmon_ru_pem_start, api_openmon_ru_pem_end-api_openmon_ru_pem_start);
        if (err != ESP_OK) {
          rlog_e(logTAG, "Failed to load certificate for OpenMon API");
          return false;
        };
      };
      vTaskDelay(1);
    #endif // _TLS_OPENMON_GLOBAL

    #if _TLS_NARODMON_GLOBAL && defined(CONFIG_NARODMON_TLS_PEM_START)
      if (api_narodmon_ru_start != default_pem_start) {
        rlog_i(logTAG, "Load certificate for NarodMon API");
        err = esp_tls_set_global_ca_store((const unsigned char*)api_narodmon_ru_pem_start, api_narodmon_ru_pem_end-api_narodmon_ru_pem_start);
        if (err != ESP_OK) {
          rlog_e(logTAG, "Failed to load certificate for NarodMon API");
          return false;
        };
      };
      vTaskDelay(1);
    #endif // _TLS_NARODMON_GLOBAL

    #if _TLS_THINGSPEAK_GLOBAL && defined(CONFIG_THINGSPEAK_TLS_PEM_START)
      if (api_thingspeak_pem_start != default_pem_start) {
        rlog_i(logTAG, "Load certificate for Thingspeak API");
        err = esp_tls_set_global_ca_store((const unsigned char*)api_thingspeak_pem_start, api_thingspeak_pem_end-api_thingspeak_pem_start);
        if (err != ESP_OK) {
          rlog_e(logTAG, "Failed to load certificate for Thingspeak API");
          return false;
        };
      };
      vTaskDelay(1);
    #endif // _TLS_THINGSPEAK_GLOBAL

    #if _TLS_OTA_GLOBAL && defined(CONFIG_OTA_PEM_START)
      if (ota_pem_start != default_pem_start) {
        rlog_i(logTAG, "Load certificate for OTA");
        err = esp_tls_set_global_ca_store((const unsigned char*)ota_pem_start, ota_pem_end-ota_pem_start);
        if (err != ESP_OK) {
          rlog_e(logTAG, "Failed to load certificate for OTA");
          return false;
        };
      };
      vTaskDelay(1);
    #endif // _TLS_OTA_GLOBAL

    #if _TLS_MQTT1_GLOBAL && defined(CONFIG_MQTT1_TLS_PEM_START)
      if (mqtt1_pem_start != default_pem_start) {
        rlog_i(logTAG, "Load certificate for MQTT #1");
        err = esp_tls_set_global_ca_store((const unsigned char*)mqtt1_pem_start, mqtt1_pem_end-mqtt1_pem_start);
        if (err != ESP_OK) {
          rlog_e(logTAG, "Failed to load certificate for MQTT #1");
          return false;
        };
      };
      vTaskDelay(1);
    #endif // _TLS_MQTT1_GLOBAL

    #if _TLS_MQTT2_GLOBAL && defined(CONFIG_MQTT2_TLS_PEM_START)
      if (mqtt2_pem_start != default_pem_start) {
        rlog_i(logTAG, "Load certificate for MQTT #2");
        err = esp_tls_set_global_ca_store((const unsigned char*)mqtt2_pem_start, mqtt2_pem_end-mqtt2_pem_start);
        if (err != ESP_OK) {
          rlog_e(logTAG, "Failed to load certificate for MQTT #2");
          return false;
        };
      };
      vTaskDelay(1);
    #endif // _TLS_MQTT2_GLOBAL

    rlog_i(logTAG, "Global certificates loaded successfully");
  #endif // _TLS_GLOBAL_ENABLED
  
  return true;
}

void freeTlsGlobalCAStore()
{
  #if _TLS_GLOBAL_ENABLED
    esp_tls_free_global_ca_store();
  #endif // _TLS_GLOBAL_ENABLED
}