/*
 *  include/scst_debug.h
 *  
 *  Copyright (C) 2004-2007 Vladislav Bolkhovitin <vst@vlnb.net>
 *                 and Leonid Stoljar
 *  
 *  Contains macroses for execution tracing and error reporting
 * 
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation, version 2
 *  of the License.
 * 
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#ifndef __SCST_DEBUG_H
#define __SCST_DEBUG_H

#include <linux/autoconf.h>	/* for CONFIG_* */
#include <asm/bug.h>		/* for WARN_ON_ONCE */

#if !defined(EXTRACHECKS) && defined(CONFIG_SCSI_TARGET_EXTRACHECKS)
#define EXTRACHECKS
#endif

#if !defined(TRACING) && defined(CONFIG_SCSI_TARGET_TRACING)
#define TRACING
#endif

#if !defined(DEBUG) && defined(CONFIG_SCSI_TARGET_DEBUG)
#define DEBUG
#endif

#ifdef DEBUG

#ifndef EXTRACHECKS
#define EXTRACHECKS
#endif

#ifndef CONFIG_DEBUG_BUGVERBOSE
#define sBUG() do {						\
	printk(KERN_CRIT "BUG at %s:%d\n",			\
	       __FILE__, __LINE__);				\
	BUG();							\
} while (0)
#else
#define sBUG() BUG()
#endif

#define sBUG_ON(p) do {						\
	if (unlikely(p)) {					\
		printk(KERN_CRIT "BUG at %s:%d (%s)\n",		\
		       __FILE__, __LINE__, #p);			\
		BUG();						\
	}							\
} while (0)

#else

#define sBUG() BUG()
#define sBUG_ON(p) BUG_ON(p)

#endif

#ifndef WARN_ON_ONCE
#define WARN_ON_ONCE(condition)	({				\
	static int __warned;					\
	typeof(condition) __ret_warn_once = (condition);	\
								\
	if (unlikely(__ret_warn_once))				\
		__warned = 1;					\
	unlikely(__ret_warn_once);				\
})
#endif

#ifdef EXTRACHECKS
#define EXTRACHECKS_BUG_ON(a)		sBUG_ON(a)
#define EXTRACHECKS_WARN_ON(a)		WARN_ON(a)
#define EXTRACHECKS_WARN_ON_ONCE(a)	WARN_ON_ONCE(a)
#else
#define EXTRACHECKS_BUG_ON(a)
#define EXTRACHECKS_WARN_ON(a)
#define EXTRACHECKS_WARN_ON_ONCE(a)
#endif

#ifdef DEBUG
//#  define LOG_FLAG KERN_DEBUG
#  define LOG_FLAG KERN_INFO

#  define INFO_FLAG KERN_INFO
#  define ERROR_FLAG KERN_INFO
#else
# define LOG_FLAG KERN_INFO
# define INFO_FLAG KERN_INFO
# define ERROR_FLAG KERN_ERR
#endif

#define NO_FLAG ""

#define TRACE_NULL           0x00000000
#define TRACE_DEBUG          0x00000001
#define TRACE_FUNCTION       0x00000002
#define TRACE_LINE           0x00000004
#define TRACE_PID            0x00000008
#define TRACE_ENTRYEXIT      0x00000010
#define TRACE_BUFF           0x00000020
#define TRACE_MEMORY         0x00000040
#define TRACE_SG             0x00000080
#define TRACE_OUT_OF_MEM     0x00000100
#define TRACE_MINOR          0x00000200 /* less important events */
#define TRACE_MGMT           0x00000400
#define TRACE_MGMT_DEBUG     0x00000800
#define TRACE_SCSI           0x00001000
#define TRACE_SPECIAL        0x00002000 /* filtering debug, etc */
#define TRACE_ALL            0xffffffff
/* Flags 0xXXXX0000 are local for users */

#define PRINT(log_flag, format, args...)  printk(log_flag format "\n", ## args);
#define PRINTN(log_flag, format, args...) printk(log_flag format, ## args);

#if defined(DEBUG) || defined(TRACING)

extern int debug_print_prefix(unsigned long trace_flag, const char *func, int line);
extern void debug_print_buffer(const void *data, int len);

#define TRACE(trace, format, args...)                               \
do {                                                                \
  if (trace_flag & (trace))                                         \
  {                                                                 \
    char *__tflag = LOG_FLAG;                                       \
    if (debug_print_prefix(trace_flag, __FUNCTION__, __LINE__) > 0) \
    {                                                               \
      __tflag = NO_FLAG;                                            \
    }                                                               \
    PRINT(NO_FLAG, "%s" format, __tflag, args);                     \
  }                                                                 \
} while(0)

#define TRACE_LOG_FLAG(log_flag, trace, format, args...)            \
do {                                                                \
  char *__tflag = log_flag;                                         \
  if (trace_flag & (trace))                                         \
  {                                                                 \
    if (debug_print_prefix(trace_flag, __FUNCTION__, __LINE__) > 0) \
    {                                                               \
      __tflag = NO_FLAG;                                            \
    }                                                               \
  }                                                                 \
  PRINT(NO_FLAG, "%s" format, __tflag, args);                       \
} while(0)

#define TRACE_BUFFER(message, buff, len)                            \
do {                                                                \
  if (trace_flag & TRACE_BUFF)                                      \
  {                                                                 \
    char *__tflag = LOG_FLAG;                                       \
    if (debug_print_prefix(trace_flag, __FUNCTION__, __LINE__) > 0) \
    {                                                               \
      __tflag = NO_FLAG;                                            \
    }                                                               \
    PRINT(NO_FLAG, "%s%s:", __tflag, message);                      \
    debug_print_buffer(buff, len);  		                    \
  }                                                                 \
} while(0)

#define TRACE_BUFF_FLAG(flag, message, buff, len)                   \
do {                                                                \
  if (trace_flag & (flag))                                          \
  {                                                                 \
    char *__tflag = LOG_FLAG;                                       \
    if (debug_print_prefix(trace_flag, __FUNCTION__, __LINE__) > 0) \
    {                                                               \
      __tflag = NO_FLAG;                                            \
    }                                                               \
    PRINT(NO_FLAG, "%s%s:", __tflag, message);                      \
    debug_print_buffer(buff, len);                                  \
  }                                                                 \
} while(0)

#else  /* DEBUG || TRACING */

#define TRACE(trace, args...) {}
#define TRACE_BUFFER(message, buff, len) {}
#define TRACE_BUFF_FLAG(flag, message, buff, len) {}

#endif /* DEBUG || TRACING */

#ifdef DEBUG

#define TRACE_MEM(format, args...)		                    \
do {                                                                \
  if (trace_flag & TRACE_MEMORY)                                    \
  {                                                                 \
    char *__tflag = LOG_FLAG;                                       \
    if (debug_print_prefix(trace_flag, __FUNCTION__, __LINE__) > 0) \
    {                                                               \
      __tflag = NO_FLAG;                                            \
    }                                                               \
    PRINT(NO_FLAG, "%s" format, __tflag, args);                     \
  }                                                                 \
} while(0)

#define TRACE_DBG(format, args...)		                    \
do {                                                                \
  if (trace_flag & TRACE_DEBUG)                                     \
  {                                                                 \
    char *__tflag = LOG_FLAG;                                       \
    if (debug_print_prefix(trace_flag, __FUNCTION__, __LINE__) > 0) \
    {                                                               \
      __tflag = NO_FLAG;                                            \
    }                                                               \
    PRINT(NO_FLAG, "%s" format, __tflag, args);                     \
  }                                                                 \
} while(0)

#define TRACE_MGMT_DBG(format, args...)		                    \
do {                                                                \
  if (trace_flag & TRACE_MGMT_DEBUG)                                \
  {                                                                 \
    char *__tflag = LOG_FLAG;                                       \
    if (debug_print_prefix(trace_flag, __FUNCTION__, __LINE__) > 0) \
    {                                                               \
      __tflag = NO_FLAG;                                            \
    }                                                               \
    PRINT(NO_FLAG, "%s" format, __tflag, args);                     \
  }                                                                 \
} while(0)

#define PRINT_ERROR_PR(format, args...)                             \
do {                                                                \
  if (ERROR_FLAG != LOG_FLAG)                                       \
  {                                                                 \
    TRACE_LOG_FLAG(LOG_FLAG, trace_flag, "%s: ***ERROR*** " format, \
    	LOG_PREFIX, args);			                    \
  }                                                                 \
  TRACE_LOG_FLAG(ERROR_FLAG, trace_flag, "%s: ***ERROR*** " format, \
  	LOG_PREFIX, args);			                    \
} while(0)

#define PRINT_INFO_PR(format, args...)          \
do {                                            \
  if (INFO_FLAG != LOG_FLAG)                    \
  {                                             \
    TRACE_LOG_FLAG(LOG_FLAG, trace_flag, "%s: " \
    	format, LOG_PREFIX, args);		\
  }                                             \
  TRACE_LOG_FLAG(INFO_FLAG, trace_flag, "%s: "	\
  	format, LOG_PREFIX, args);		\
} while(0)

#define PRINT_ERROR(format, args...)		                       \
do {                                                                   \
  if (ERROR_FLAG != LOG_FLAG)                                          \
  {                                                                    \
    TRACE_LOG_FLAG(LOG_FLAG, trace_flag, "***ERROR*** " format, args); \
  }                                                                    \
  TRACE_LOG_FLAG(ERROR_FLAG, trace_flag, "***ERROR*** " format, args); \
} while(0)

#define PRINT_INFO(format, args...)                     \
do {                                                    \
  if (INFO_FLAG != LOG_FLAG)                            \
  {                                                     \
    TRACE_LOG_FLAG(LOG_FLAG, trace_flag, format, args); \
  }                                                     \
  TRACE_LOG_FLAG(INFO_FLAG, trace_flag, format, args);  \
} while(0)

#define TRACE_ENTRY()                                 \
do {                                                  \
  if (trace_flag & TRACE_ENTRYEXIT)                   \
  {                                                   \
    if (trace_flag & TRACE_PID)                       \
    {                                                 \
      PRINT(LOG_FLAG, "[%d]: ENTRY %s", current->pid, \
          __FUNCTION__);                              \
    }                                                 \
    else                                              \
    {                                                 \
      PRINT(LOG_FLAG, "ENTRY %s", __FUNCTION__);      \
    }                                                 \
  }                                                   \
} while(0)

#define TRACE_EXIT()                                 \
do {                                                 \
  if (trace_flag & TRACE_ENTRYEXIT)                  \
  {                                                  \
    if (trace_flag & TRACE_PID)                      \
    {                                                \
      PRINT(LOG_FLAG, "[%d]: EXIT %s", current->pid, \
          __FUNCTION__);		             \
    }                                                \
    else                                             \
    {                                                \
      PRINT(LOG_FLAG, "EXIT %s", __FUNCTION__);      \
    }                                                \
  }                                                  \
} while(0)

#define TRACE_EXIT_RES(res)                                       \
do {                                                              \
  if (trace_flag & TRACE_ENTRYEXIT)                               \
  {                                                               \
    if (trace_flag & TRACE_PID)                                   \
    {                                                             \
      PRINT(LOG_FLAG, "[%d]: EXIT %s: %ld", current->pid,         \
        __FUNCTION__, (long)(res));                               \
    }                                                             \
    else                                                          \
    {                                                             \
      PRINT(LOG_FLAG, "EXIT %s: %ld", __FUNCTION__, (long)(res)); \
    }                                                             \
  }                                                               \
} while(0)

#define TRACE_EXIT_HRES(res)                                      \
do {                                                              \
  if (trace_flag & TRACE_ENTRYEXIT)                               \
  {                                                               \
    if (trace_flag & TRACE_PID)                                   \
    {                                                             \
      PRINT(LOG_FLAG, "[%d]: EXIT %s: 0x%lx", current->pid,       \
        __FUNCTION__, (long)(res));                               \
    }                                                             \
    else                                                          \
    {                                                             \
      PRINT(LOG_FLAG, "EXIT %s: %lx", __FUNCTION__, (long)(res)); \
    }                                                             \
  }                                                               \
} while(0)

#else  /* DEBUG */

#define TRACE_MEM(format, args...) {}
#define TRACE_DBG(format, args...) {}
#define TRACE_MGMT_DBG(format, args...) {}
#define TRACE_ENTRY() {}
#define TRACE_EXIT() {}
#define TRACE_EXIT_RES(res) {}
#define TRACE_EXIT_HRES(res) {}

#define PRINT_INFO_PR(format, args...)               \
do {                                                 \
  PRINT(INFO_FLAG, "%s: " format, LOG_PREFIX, args); \
} while(0)

#define PRINT_ERROR_PR(format, args...)         \
do {                                            \
  PRINT(ERROR_FLAG, "%s: ***ERROR*** "          \
        format, LOG_PREFIX, args);              \
} while(0)

#define PRINT_INFO(format, args...)           	\
do {                                            \
  PRINT(INFO_FLAG, format, args);               \
} while(0)

#define PRINT_ERROR(format, args...)          	\
do {                                            \
  PRINT(ERROR_FLAG, "***ERROR*** "              \
        format, args);                          \
} while(0)

#endif /* DEBUG */

#endif /* __SCST_DEBUG_H */
