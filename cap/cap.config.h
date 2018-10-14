#ifndef __CAP_CONFIG__
#define __CAP_CONFIG__

#if (defined(WIN32) || defined(_WIN32) || defined(__WIN32)) && !defined(__CYGWIN__)
#define CAP_WIN_NATIVE
#endif

#if defined(__CYGWIN__)
#define CAP_CYGWIN
#endif

#if defined(CAP_WIN_NATIVE) || defined(CAP_CYGWIN)
#define CAP_WIN32
#endif

#if !defined(SIO_WIN_NATIVE)
#define CAP_POSIX
#endif

#if defined(_MSC_VER)
#define CAP_MSVC
#if !defined(_DEBUG) && !defined(__CAP_INLINE__)
#define __CAP_INLINE__
#endif
#endif

#if defined(__GNUC__)
#define CAP_GCC
#if __GNUC__ < 4
#define CAP_GCC3
#endif
#if !defined (__CAP_INLINE__)
#define __CAP_INLINE__
#endif
#endif

#if defined(CAP_LACKS_INLINE_FUNCTIONS) && !defined(CAP_NO_INLINE)
#define CAP_NO_INLINE
#endif

#if defined(CAP_NO_INLINE)
#undef __CAP_INLINE__
#endif

#if defined(__CAP_INLINE__)
#define CAP_INLINE inline
#else
#define CAP_INLINE
#endif

#if defined(__linux)
#elif defined(__sun) || defined(__hpux)
#elif defined(__FreeBSD__) || defined(__NetBSD__)
#define CAP_USE_OPEN_LIVE_TIMEOUT
#elif defined(__APPLE__)
#define CAP_USE_OPEN_LIVE_TIMEOUT
#elif defined(__CYGWIN__) || defined(__WIN32) || defined(_WIN32) || defined(WIN32)
#else // generic POSIX
#endif

#if defined(CAP_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#if !defined(CAP_LACKS_NETINET_IN_H)
#include <netinet/in.h>
#endif
#if !defined(CAP_LACKS_ARPA_INET_H)
#include <arpa/inet.h>
#endif
#if !defined(CAP_LACKS_SYS_TYPES_H)
#include <sys/types.h>
#endif
#if !defined(CAP_LACKS_SYS_SOCKET_H)
#include <sys/socket.h>
#endif
#endif

#endif

