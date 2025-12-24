/* Copyright  (C) 2010-2020 The RetroArch team
 *
 * ---------------------------------------------------------------------------------------
 * The following license statement only applies to this file (net_socket.c).
 * ---------------------------------------------------------------------------------------
 *
 * Permission is hereby granted, free of charge,
 * to any person obtaining a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <string.h>
#include <net/net_compat.h>
#include <net/net_socket.h>
#include <net/net_socket_ssl.h>

#ifdef _3DS
#include <3ds/types.h>
#include <3ds/services/ps.h>
#endif

#ifdef VITA
#include <psp2/kernel/processmgr.h>
#include <psp2/rtc.h>
#endif

#if defined(HAVE_BUILTINMBEDTLS)
#include "../../deps/mbedtls/mbedtls/config.h"
#include "../../deps/mbedtls/mbedtls/certs.h"
#include "../../deps/mbedtls/mbedtls/debug.h"
#include "../../deps/mbedtls/mbedtls/platform.h"
#include "../../deps/mbedtls/mbedtls/net_sockets.h"
#include "../../deps/mbedtls/mbedtls/ssl.h"
#include "../../deps/mbedtls/mbedtls/ctr_drbg.h"
#include "../../deps/mbedtls/mbedtls/entropy.h"
#else
#include <mbedtls/version.h>
#if MBEDTLS_VERSION_MAJOR < 3
#include <mbedtls/config.h>
#include <mbedtls/certs.h>
#else
#include <mbedtls/build_info.h>
#endif
#include <mbedtls/debug.h>
#include <mbedtls/platform.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#endif

/* Not part of the mbedtls upstream source */
#include "cacert.h"

/* Enable SSL debug logging for VITA to help debug HTTPS issues */
#ifdef VITA
#define DEBUG_LEVEL 4
#else
#define DEBUG_LEVEL 0
#endif

/* Global SSL error tracking for debugging */
static int ssl_last_error_code = 0;
static char ssl_last_error_msg[256] = {0};

const char* ssl_socket_get_last_error(int *error_code)
{
   if (error_code)
      *error_code = ssl_last_error_code;
   if (ssl_last_error_code == 0)
      return NULL;
   return ssl_last_error_msg;
}

static void ssl_set_error(int code, const char *msg)
{
   ssl_last_error_code = code;
   if (msg)
      snprintf(ssl_last_error_msg, sizeof(ssl_last_error_msg), "%s", msg);
   else
      ssl_last_error_msg[0] = '\0';
}

static void ssl_clear_error(void)
{
   ssl_last_error_code = 0;
   ssl_last_error_msg[0] = '\0';
}

struct ssl_state
{
   mbedtls_net_context net_ctx;
   mbedtls_ssl_context ctx;
   mbedtls_entropy_context entropy;
   mbedtls_ctr_drbg_context ctr_drbg;
   mbedtls_ssl_config conf;
#if defined(MBEDTLS_X509_CRT_PARSE_C)
   mbedtls_x509_crt ca;
#endif
  const char *domain;
};

static void ssl_debug(void *ctx, int level,
      const char *file, int line,
      const char *str)
{
   fprintf((FILE*)ctx, "%s:%04d: %s", file, line, str);
   fflush((FILE*)ctx);
}

#ifdef _3DS
int ctr_entropy_func(void *data, unsigned char *s, size_t len)
{
   (void)data;
   PS_GenerateRandomBytes(s, len);
   return 0;
}
#endif

#ifdef VITA
int vita_entropy_func(void *data, unsigned char *s, size_t len)
{
   size_t i, j;
   SceRtcTick tick;
   SceUInt64 time_vals[4];
   SceUInt64 state;
   (void)data;

   /* Get initial entropy from RTC tick */
   sceRtcGetCurrentTick(&tick);
   state = tick.tick;

   /* Sample system time multiple times for additional entropy */
   for (j = 0; j < 4; j++)
      time_vals[j] = sceKernelGetSystemTimeWide();

   /* Mix all time values into state using XOR and rotation */
   for (j = 0; j < 4; j++)
   {
      state ^= time_vals[j];
      state = (state << 17) | (state >> 47);
      state ^= (state >> 31);
   }

   /* Generate output bytes using a simple PRNG seeded with the entropy */
   for (i = 0; i < len; i++)
   {
      /* xorshift64* PRNG for good statistical properties */
      state ^= state >> 12;
      state ^= state << 25;
      state ^= state >> 27;
      s[i] = (unsigned char)((state * 0x2545F4914F6CDD1DULL) >> 56);
   }

   return 0;
}
#endif

void* ssl_socket_init(int fd, const char *domain)
{
   int ret;
   static const char *pers = "libretro";
   struct ssl_state *state = (struct ssl_state*)calloc(1, sizeof(*state));

   ssl_clear_error();
   state->domain           = domain;

#if defined(MBEDTLS_DEBUG_C)
   mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

#ifdef VITA
   fprintf(stderr, "[SSL] ssl_socket_init: fd=%d, domain=%s\n", fd, domain ? domain : "(null)");
#endif

   mbedtls_net_init(&state->net_ctx);
   mbedtls_ssl_init(&state->ctx);
   mbedtls_ssl_config_init(&state->conf);
#if defined(MBEDTLS_X509_CRT_PARSE_C)
   mbedtls_x509_crt_init(&state->ca);
#endif
   mbedtls_ctr_drbg_init(&state->ctr_drbg);
   mbedtls_entropy_init(&state->entropy);

   state->net_ctx.fd = fd;

   ret = mbedtls_ctr_drbg_seed(&state->ctr_drbg,
#ifdef _3DS
      ctr_entropy_func,
#elif defined(VITA)
      vita_entropy_func,
#else
      mbedtls_entropy_func,
#endif
      &state->entropy, (const unsigned char*)pers, strlen(pers));
   if (ret != 0)
   {
      ssl_set_error(ret, "mbedtls_ctr_drbg_seed failed (entropy init)");
#ifdef VITA
      fprintf(stderr, "[SSL] mbedtls_ctr_drbg_seed failed: -0x%04x\n", -ret);
#endif
      goto error;
   }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
   ret = mbedtls_x509_crt_parse(&state->ca, (const unsigned char*)cacert_pem, sizeof(cacert_pem) / sizeof(cacert_pem[0]));
   if (ret < 0)
   {
      ssl_set_error(ret, "mbedtls_x509_crt_parse failed (CA cert load)");
#ifdef VITA
      fprintf(stderr, "[SSL] mbedtls_x509_crt_parse failed: -0x%04x\n", -ret);
#endif
      goto error;
   }
#ifdef VITA
   fprintf(stderr, "[SSL] CA certificates loaded successfully\n");
#endif
#endif

   return state;

error:
   if (state)
      free(state);
   return NULL;
}

int ssl_socket_connect(void *state_data,
      void *data, bool timeout_enable, bool nonblock)
{
   int ret, flags;
   struct ssl_state *state = (struct ssl_state*)state_data;

   ssl_clear_error();

#ifdef VITA
   fprintf(stderr, "[SSL] ssl_socket_connect: starting connection\n");
#endif

   if (timeout_enable)
   {
      if (!socket_connect_with_timeout(state->net_ctx.fd, data, 5000))
      {
#ifdef VITA
         extern int g_vita_last_connect_error;
         char err_buf[128];
         snprintf(err_buf, sizeof(err_buf), "socket_connect_with_timeout failed (VITA err: 0x%08X)", 
                  (unsigned int)g_vita_last_connect_error);
         ssl_set_error(g_vita_last_connect_error, err_buf);
         fprintf(stderr, "[SSL] %s\n", err_buf);
#else
         ssl_set_error(-1, "socket_connect_with_timeout failed");
#endif
         return -1;
      }
      /* socket_connect_with_timeout makes the socket non-blocking (except VITA). */
      if (!socket_set_block(state->net_ctx.fd, true))
      {
         ssl_set_error(-2, "socket_set_block failed");
#ifdef VITA
         fprintf(stderr, "[SSL] socket_set_block failed\n");
#endif
         return -1;
      }
   }
   else
   {
      if (socket_connect(state->net_ctx.fd, data))
      {
         ssl_set_error(-3, "socket_connect failed");
#ifdef VITA
         fprintf(stderr, "[SSL] socket_connect failed\n");
#endif
         return -1;
      }
   }

#ifdef VITA
   fprintf(stderr, "[SSL] Socket connected, configuring SSL\n");
#endif

   ret = mbedtls_ssl_config_defaults(&state->conf,
               MBEDTLS_SSL_IS_CLIENT,
               MBEDTLS_SSL_TRANSPORT_STREAM,
               MBEDTLS_SSL_PRESET_DEFAULT);
   if (ret != 0)
   {
      ssl_set_error(ret, "mbedtls_ssl_config_defaults failed");
#ifdef VITA
      fprintf(stderr, "[SSL] mbedtls_ssl_config_defaults failed: -0x%04x\n", -ret);
#endif
      return -1;
   }

   mbedtls_ssl_conf_authmode(&state->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
   mbedtls_ssl_conf_ca_chain(&state->conf, &state->ca, NULL);
   mbedtls_ssl_conf_rng(&state->conf, mbedtls_ctr_drbg_random, &state->ctr_drbg);
   mbedtls_ssl_conf_dbg(&state->conf, ssl_debug, stderr);

   ret = mbedtls_ssl_setup(&state->ctx, &state->conf);
   if (ret != 0)
   {
      ssl_set_error(ret, "mbedtls_ssl_setup failed");
#ifdef VITA
      fprintf(stderr, "[SSL] mbedtls_ssl_setup failed: -0x%04x\n", -ret);
#endif
      return -1;
   }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
   ret = mbedtls_ssl_set_hostname(&state->ctx, state->domain);
   if (ret != 0)
   {
      ssl_set_error(ret, "mbedtls_ssl_set_hostname failed");
#ifdef VITA
      fprintf(stderr, "[SSL] mbedtls_ssl_set_hostname failed: -0x%04x\n", -ret);
#endif
      return -1;
   }
#endif

   mbedtls_ssl_set_bio(&state->ctx, &state->net_ctx, mbedtls_net_send, mbedtls_net_recv, NULL);

#ifdef VITA
   fprintf(stderr, "[SSL] Starting SSL handshake with %s\n", state->domain ? state->domain : "(null)");
#endif

   while ((ret = mbedtls_ssl_handshake(&state->ctx)) != 0)
   {
      if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
      {
         ssl_set_error(ret, "mbedtls_ssl_handshake failed");
#ifdef VITA
         fprintf(stderr, "[SSL] mbedtls_ssl_handshake failed: -0x%04x\n", -ret);
#endif
         return -1;
      }
   }

#ifdef VITA
   fprintf(stderr, "[SSL] SSL handshake completed successfully\n");
#endif

   if ((flags = mbedtls_ssl_get_verify_result(&state->ctx)) != 0)
   {
      char vrfy_buf[512];
      mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
#ifdef VITA
      fprintf(stderr, "[SSL] Certificate verification: %s\n", vrfy_buf);
#endif
   }

   return state->net_ctx.fd;
}

ssize_t ssl_socket_receive_all_nonblocking(void *state_data,
      bool *err, void *data_, size_t len)
{
   ssize_t ret;
   struct ssl_state *state = (struct ssl_state*)state_data;
   unsigned char     *data = (unsigned char*)data_;
   size_t       total_read = 0;
   int      max_iterations = 8;  /* Limit iterations to prevent infinite loops */

   mbedtls_net_set_nonblock(&state->net_ctx);

   /* Keep reading while we get data without blocking, up to max iterations
    * This allows us to read multiple TLS records (16KB each) in one call */
   while (len > 0 && max_iterations-- > 0)
   {
      ret = mbedtls_ssl_read(&state->ctx, data, len);

      if (ret > 0)
      {
         total_read += ret;
         data += ret;
         len -= ret;

         /* If we read less than requested, there's likely no more data available
          * But check if there's buffered data we can read without blocking */
         if ((size_t)ret < len)
         {
            size_t bytes_avail = mbedtls_ssl_get_bytes_avail(&state->ctx);
            if (bytes_avail == 0)

               break;  /* No more buffered data, don't risk blocking */
         }
         /* Continue looping to read more records */
      }
      else if (ret == 0)
      {
         /* Socket closed */
         if (total_read > 0)
            return total_read;  /* Return what we got before close */
         *err = true;
         return -1;
      }
      else if (isagain((int)ret) || ret == MBEDTLS_ERR_SSL_WANT_READ)
      {
         /* Would block - return what we have so far */
         if (total_read > 0)
            return total_read;
         return 0;  /* No data available yet */
      }
      else
      {
         /* Error */
         if (total_read > 0)
            return total_read;  /* Return what we got before error */
         *err = true;
         return -1;
      }
   }

   return total_read;
}

int ssl_socket_receive_all_blocking(void *state_data,
      void *data_, size_t len)
{
   struct ssl_state *state = (struct ssl_state*)state_data;
   const uint8_t     *data = (const uint8_t*)data_;

   mbedtls_net_set_block(&state->net_ctx);

   for (;;)
   {
      /* mbedtls_ssl_read wants non-const data but it only reads it,
       * so this cast is safe */
      int ret = mbedtls_ssl_read(&state->ctx, (unsigned char*)data, len);

      if (     ret == MBEDTLS_ERR_SSL_WANT_READ
            || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
         continue;

      if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
         break;

      if (ret == 0)
         break; /* normal EOF */

      if (ret < 0)
         return -1;
   }

   return 1;
}

int ssl_socket_send_all_blocking(void *state_data,
      const void *data_, size_t len, bool no_signal)
{
   int ret;
   struct ssl_state *state = (struct ssl_state*)state_data;
   const     uint8_t *data = (const uint8_t*)data_;

   mbedtls_net_set_block(&state->net_ctx);

   while (len)
   {
      ret = mbedtls_ssl_write(&state->ctx, data, len);

      if (!ret)
         continue;

      if (ret < 0)
      {
         if (  ret != MBEDTLS_ERR_SSL_WANT_READ &&
              ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            return false;
      }
      else
      {
          data += ret;
          len  -= ret;
      }
   }

   return true;
}

ssize_t ssl_socket_send_all_nonblocking(void *state_data,
      const void *data_, size_t len, bool no_signal)
{
   int ret;
   ssize_t __len = len;
   struct ssl_state *state = (struct ssl_state*)state_data;
   const uint8_t     *data = (const uint8_t*)data_;
   mbedtls_net_set_nonblock(&state->net_ctx);
   ret = mbedtls_ssl_write(&state->ctx, data, len);
   if (ret <= 0)
      return -1;
   return __len;
}

void ssl_socket_close(void *state_data)
{
   struct ssl_state *state = (struct ssl_state*)state_data;

   mbedtls_ssl_close_notify(&state->ctx);

   socket_close(state->net_ctx.fd);
}

void ssl_socket_free(void *state_data)
{
   struct ssl_state *state = (struct ssl_state*)state_data;

   if (!state)
      return;

   mbedtls_ssl_free(&state->ctx);
   mbedtls_ssl_config_free(&state->conf);
   mbedtls_ctr_drbg_free(&state->ctr_drbg);
   mbedtls_entropy_free(&state->entropy);
#if defined(MBEDTLS_X509_CRT_PARSE_C)
   mbedtls_x509_crt_free(&state->ca);
#endif

   free(state);
}
