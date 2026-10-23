/* SPDX-License-Identifier: GPL-2.0-only */
/* Parser definitions appended by model.py, not compiler definitions. */
#define SCST_KUNIT_VISIBLE
#define SCST_KUNIT_VISIBLE_INLINE inline

/* standard.h defines TRACE_EXIT as return; SCST only logs at this point. */
#define TRACE_EXIT scst_cocci_trace_exit

/* The parser does not accept its annotation token after a bitfield width.
 * Alignment has no control-flow effect; keep the field declaration visible.
 */
#define __aligned(n)
#define __nonstring MACROANNOTATION

/* RDMA conftests select const for current ib_post_{send,recv} bad-WR pointers.
 * Older APIs omit the qualifier; neither form changes the function body.
 */
#define BAD_WR_MODIFIER const

/* Kernel iterator: keep the loop body visible to semantic-patch rules. */
/* checkpatch-suppress MACRO_ARG_UNUSED ; Coccinelle iterator parser token. */
#define for_each_possible_cpu(cpu) YACFE_ITERATOR

/* String-valued fragments, including hashes from generated headers. */
#define SCST_VERSION_NAME YACFE_STRING
#define SCST_VERSION_STRING_SUFFIX YACFE_STRING
#define SCST_VERSION_STRING YACFE_STRING
#define SCST_INTF_VER YACFE_STRING
#define SCST_CONST_VERSION YACFE_STRING
#define DEV_USER_VERSION_NAME YACFE_STRING
#define DEV_USER_INTF_VER YACFE_STRING
#define SCST_EVENT_PATH YACFE_STRING
#define SCST_EVENT_NAME YACFE_STRING
#define SCST_NAMESPACE YACFE_STRING
