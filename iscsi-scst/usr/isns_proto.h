/*
 * iSNS protocol data types
 *
 * Copyright (C) 2006 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2007 - 2018 Vladislav Bolkhovitin
 * Copyright (C) 2007 - 2018 Western Digital Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.
 */

#ifndef ISNS_PROTO_H
#define ISNS_PROTO_H

#define ISNS_PORT	3205
#define ISNS_ALIGN	4

struct isns_hdr {
	uint16_t version;
	uint16_t function;
	uint16_t length;
	uint16_t flags;
	uint16_t transaction;
	uint16_t sequence;
	uint32_t pdu[];
} __attribute__ ((packed));

struct isns_tlv {
	uint32_t tag;
	uint32_t length;
	uint32_t value[];
} __attribute__ ((packed));

/* Commands and responses (4.1.3) */
#define ISNS_FUNC_DEV_ATTR_REG			0x0001
#define ISNS_FUNC_DEV_ATTR_QRY			0x0002
#define ISNS_FUNC_DEV_GET_NEXT			0x0003
#define ISNS_FUNC_DEV_DEREG			0x0004
#define ISNS_FUNC_SCN_REG			0x0005
#define ISNS_FUNC_SCN_DEREG			0x0006
#define ISNS_FUNC_SCN_EVENT			0x0007
#define ISNS_FUNC_SCN				0x0008
#define ISNS_FUNC_DD_REG			0x0009
#define ISNS_FUNC_DD_DEREG			0x000a
#define ISNS_FUNC_DDS_REG			0x000b
#define ISNS_FUNC_DDS_DEREG			0x000c
#define ISNS_FUNC_ESI				0x000d
#define ISNS_FUNC_HEARTBEAT			0x000e

#define ISNS_FUNC_DEV_ATTR_REG_RSP		0x8001
#define ISNS_FUNC_DEV_ATTR_QRY_RSP		0x8002
#define ISNS_FUNC_DEV_GET_NEXT_RSP		0x8003
#define ISNS_FUNC_DEV_DEREG_RSP			0x8004
#define ISNS_FUNC_SCN_REG_RSP			0x8005
#define ISNS_FUNC_SCN_DEREG_RSP			0x8006
#define ISNS_FUNC_SCN_EVENT_RSP			0x8007
#define ISNS_FUNC_SCN_RSP			0x8008
#define ISNS_FUNC_DD_REG_RSP			0x8009
#define ISNS_FUNC_DD_DEREG_RSP			0x800a
#define ISNS_FUNC_DDS_REG_RSP			0x800b
#define ISNS_FUNC_DDS_DEREG_RSP			0x800c
#define ISNS_FUNC_ESI_RSP			0x800d

/* iSNSP flags (5.1.4) */
#define ISNS_FLAG_CLIENT			(1U << 15)
#define ISNS_FLAG_SERVER			(1U << 14)
#define ISNS_FLAG_AUTH				(1U << 13)
#define ISNS_FLAG_REPLACE			(1U << 12)
#define ISNS_FLAG_LAST_PDU			(1U << 11)
#define ISNS_FLAG_FIRST_PDU			(1U << 10)

/* Response Status Codes (5.4) */
#define ISNS_STATUS_SUCCESS			0
#define ISNS_STATUS_UNKNOWN_ERROR		1
#define ISNS_STATUS_FORMAT_ERROR		2
#define ISNS_STATUS_INVALID_REGISTRATION	3
#define ISNS_STATUS_RESERVED			4
#define ISNS_STATUS_INVALID_QUERY		5
#define ISNS_STATUS_SOURCE_UNKNOWN		6
#define ISNS_STATUS_SOURCE_ABSENT		7
#define ISNS_STATUS_SOURCE_UNAUTHORIZED		8
#define ISNS_STATUS_NO_SUCH_ENTRY		9
#define ISNS_STATUS_VERSION_NOT_SUPPORTED	10
#define ISNS_STATUS_INTERNAL_ERROR		11
#define ISNS_STATUS_BUSY			12
#define ISNS_STATUS_OPTION_NOT_UNDERSTOOD	13
#define ISNS_STATUS_INVALID_UPDATE		14
#define ISNS_STATUS_MESSAGE_NOT_SUPPORTED	15
#define ISNS_STATUS_SCN_EVENT_REJECTED		16
#define ISNS_STATUS_SCN_REGISTRATION_REJECTED	17
#define ISNS_STATUS_ATTRIBUTE_NOT_IMPLEMENTED	18
#define ISNS_STATUS_FC_DOMAIN_ID_NOT_AVAILABLE	19
#define ISNS_STATUS_FC_DOMAIN_ID_NOT_ALLOCATED	20
#define ISNS_STATUS_ESI_NOT_AVAILABLE		21
#define ISNS_STATUS_INVALIDE_DEREGISTRATION	22
#define ISNS_STATUS_REGISTRATION_NOT_SUPPORTED	23

/* Node type (5.4.2) */
#define ISNS_NODE_CONTROL			(1U << 2)
#define ISNS_NODE_INITIATOR			(1U << 1)
#define ISNS_NODE_TARGET			(1U << 0)

/* Attributes (6.1) */
#define ISNS_ATTR_DELIMITER			0
#define ISNS_ATTR_ENTITY_IDENTIFIER		1
#define ISNS_ATTR_ENTITY_PROTOCOL		2
#define ISNS_ATTR_MANAGEMENT_IP_ADDRESS		3
#define ISNS_ATTR_TIMESTAMP			4
#define ISNS_ATTR_PROTOCOL_VERSION_RANGE	5
#define ISNS_ATTR_REGISTRATION_PERIOD		6
#define ISNS_ATTR_ENTITY_INDEX			7
#define ISNS_ATTR_ENTITY_NEXT_INDEX		8
#define ISNS_ATTR_ISAKMP_PHASE1			11
#define ISNS_ATTR_CERTIFICATE			12
#define ISNS_ATTR_PORTAL_IP_ADDRESS		16
#define ISNS_ATTR_PORTAL_PORT			17
#define ISNS_ATTR_PORTAL_SYMBOLIC_NAME		18
#define ISNS_ATTR_ESI_INTERVAL			19
#define ISNS_ATTR_ESI_PORT			20
#define ISNS_ATTR_PORTAL_INDEX			22
#define ISNS_ATTR_SCN_PORT			23
#define ISNS_ATTR_PORTAL_NEXT_INDEX		24
#define ISNS_ATTR_PORTAL_SECURITY_BITMAP	27
#define ISNS_ATTR_PORTAL_ISAKMP_PHASE1		28
#define ISNS_ATTR_PORTAL_ISAKMP_PHASE2		29
#define ISNS_ATTR_PORTAL_CERTIFICATE		31
#define ISNS_ATTR_ISCSI_NAME			32
#define ISNS_ATTR_ISCSI_NODE_TYPE		33
#define ISNS_ATTR_ISCSI_ALIAS			34
#define ISNS_ATTR_ISCSI_SCN_BITMAP		35
#define ISNS_ATTR_ISCSI_NODE_INDEX		36
#define ISNS_ATTR_WWNN_TOKEN			37
#define ISNS_ATTR_ISCSI_NODE_NEXT_INDEX		38
#define ISNS_ATTR_ISCSI_AUTHMETHOD		42
#define ISNS_ATTR_PG_ISCSI_NAME			48
#define ISNS_ATTR_PG_PORTAL_IP_ADDRESS		49
#define ISNS_ATTR_PG_PORTAL_PORT		50
#define ISNS_ATTR_PG_TAG			51
#define ISNS_ATTR_PG_INDEX			52
#define ISNS_ATTR_PG_NEXT_INDEX			53
#define ISNS_ATTR_FC_PORT_NAME_WWPN		64
#define ISNS_ATTR_PORT_ID			65
#define ISNS_ATTR_PORT_TYPE			66
#define ISNS_ATTR_SYMBOLIC_PORT_NAME		67
#define ISNS_ATTR_FABRIC_PORT_NAME		68
#define ISNS_ATTR_HARD_ADDRESS			69
#define ISNS_ATTR_PORT_IP_ADDRESS		70
#define ISNS_ATTR_CLASS_OF_SERVICE		71
#define ISNS_ATTR_FC4_TYPES			72
#define ISNS_ATTR_FC4_DESCRIPOTR		73
#define ISNS_ATTR_FC4_FEATURES			74
#define ISNS_ATTR_IFCP_SCN_BITMAP		75
#define ISNS_ATTR_PORT_ROLE			76
#define ISNS_ATTR_PERMANENT_PORT_NAME		77
#define ISNS_ATTR_FC4_TYPE_CODE			95
#define ISNS_ATTR_FC_NODE_NAME_WWNN		96
#define ISNS_ATTR_SYMBOLIC_NODE_NAME		97
#define ISNS_ATTR_NODE_IP_ADDRESS		98
#define ISNS_ATTR_NODE_IPA			99
#define ISNS_ATTR_PORXY_ISCSI_NAME		101
#define ISNS_ATTR_SWITCH_NAME			128
#define ISNS_ATTR_PREFERRED_ID			129
#define ISNS_ATTR_ASSIGNED_ID			130
#define ISNS_ATTR_VIRTUAL_FABRIC_ID		131
#define ISNS_ATTR_ISNS_SERVER_VENDOR_OUI	256
#define ISNS_ATTR_DD_SET_ID			2049
#define ISNS_ATTR_DD_SET_SYM_NAME		2050
#define ISNS_ATTR_DD_SET_STATUS			2051
#define ISNS_ATTR_DD_SET_NEXT_ID		2052
#define ISNS_ATTR_DD_ID				2065
#define ISNS_ATTR_DD_SYMBOLIC_NAME		2066
#define ISNS_ATTR_DD_MEMBER_ISCSI_INDEX		2067
#define ISNS_ATTR_DD_MEMBER_ISCSI_NAME		2068
#define ISNS_ATTR_DD_MEMBER_FC_PORT_NAME	2069
#define ISNS_ATTR_DD_MEMBER_PORTAL_INDEX	2070
#define ISNS_ATTR_DD_MEMBER_IP_ADDR		2071
#define ISNS_ATTR_DD_MEMBER_TCP_UDP		2072
#define ISNS_ATTR_DD_FEATURES			2078
#define ISNS_ATTR_DD_ID_NEXT_ID			2079

/* SCN flags (6.4.4) */
#define ISNS_SCN_FLAG_INITIATOR			(1U << 24)
#define ISNS_SCN_FLAG_TARGET			(1U << 25)
#define ISNS_SCN_FLAG_MANAGEMENT		(1U << 26)
#define ISNS_SCN_FLAG_OBJECT_REMOVE		(1U << 27)
#define ISNS_SCN_FLAG_OBJECT_ADDED		(1U << 28)
#define ISNS_SCN_FLAG_OBJECT_UPDATED		(1U << 29)
#define ISNS_SCN_FLAG_DD_REMOVED		(1U << 30)
#define ISNS_SCN_FLAG_DD_ADDED			(1U << 31)
#endif
