/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_ISCSI_NTHREAD_H
#define SCST_ISCSI_NTHREAD_H

enum tx_state {
	TX_INIT = 0, /* Must be zero for better "switch" optimization. */
	TX_BHS_DATA,
	TX_INIT_PADDING,
	TX_PADDING,
	TX_INIT_DDIGEST,
	TX_DDIGEST,
	TX_END,
};

#endif /* SCST_ISCSI_NTHREAD_H */
