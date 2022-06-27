/* 
   EN: Uploading certificates to a centralized store
   RU: Загрузка сертификатов в централизованное хранилище
   --------------------------
   (с) 2022 Разживин Александр | Razzhivin Alexander
   kotyara12@yandex.ru | https://kotyara12.ru | tg: @kotyara1971
*/

#ifndef __RE_CERTS_H__
#define __RE_CERTS_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

bool initTlsGlobalCAStore();
void freeTlsGlobalCAStore();

#ifdef __cplusplus
}
#endif

#endif // __RE_CERTS_H__
