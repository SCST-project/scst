/*
 * The file has no complete file-specific license grant; do not infer one solely
 * from adjacent sources. Defer SPDX conversion pending provenance/maintainer
 * resolution; this exception covers only the missing tag in this exact existing
 * source.
 */
/* checkpatch-suppress-file SPDX_LICENSE_TAG ; See the contract above. */
#ifndef _SCST_LOCAL_CMD_H_
#define _SCST_LOCAL_CMD_H_

enum scst_exec_res;
struct scst_cmd;

enum scst_exec_res scst_cm_ext_copy_exec(struct scst_cmd *ec_cmd);
enum scst_exec_res scst_cm_rcv_copy_res_exec(struct scst_cmd *cmd);
enum scst_exec_res scst_cmp_wr_local(struct scst_cmd *cmd);
enum scst_exec_res scst_maintenance_in(struct scst_cmd *cmd);
enum scst_exec_res scst_maintenance_out(struct scst_cmd *cmd);
enum scst_exec_res scst_persistent_reserve_in_local(struct scst_cmd *cmd);
enum scst_exec_res scst_persistent_reserve_out_local(struct scst_cmd *cmd);
enum scst_exec_res scst_release_local(struct scst_cmd *cmd);
enum scst_exec_res scst_release_local(struct scst_cmd *cmd);
enum scst_exec_res scst_report_luns_local(struct scst_cmd *cmd);
enum scst_exec_res scst_request_sense_local(struct scst_cmd *cmd);
enum scst_exec_res scst_reserve_local(struct scst_cmd *cmd);

#endif /* _SCST_LOCAL_CMD_H_ */
