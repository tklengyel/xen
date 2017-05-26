/*
 * noxs.h
 *
 *  Created on: Sep 16, 2016
 *      Author: Costin Lupu
 *              Filipe Manco
 */

#ifndef XEN_PUBLIC_IO_NOXS_H_
#define XEN_PUBLIC_IO_NOXS_H_

#include "../xen.h"
#include "../event_channel.h"
#include "../grant_table.h"


#define NOXS_DEV_COUNT_MAX 32


typedef uint32_t noxs_dev_id_t;


enum noxs_dev_type {
	noxs_dev_none = 0,
};
typedef enum noxs_dev_type noxs_dev_type_t;

struct noxs_dev_key {
	noxs_dev_type_t type;
	domid_t be_id;
	domid_t fe_id;
	noxs_dev_id_t devid;
};
typedef struct noxs_dev_key noxs_dev_key_t;


struct noxs_dev_comm {
	grant_ref_t grant;
	evtchn_port_t evtchn;
};
typedef struct noxs_dev_comm noxs_dev_comm_t;


struct noxs_dev_page_entry {
	noxs_dev_type_t type;
	noxs_dev_id_t id;

	domid_t be_id;
	noxs_dev_comm_t comm;
};
typedef struct noxs_dev_page_entry noxs_dev_page_entry_t;

struct noxs_dev_page {
	uint32_t version;
	uint32_t dev_count;
	noxs_dev_page_entry_t devs[NOXS_DEV_COUNT_MAX];
};
typedef struct noxs_dev_page noxs_dev_page_t;


enum noxs_watch_state {
	noxs_watch_none = 0,
	noxs_watch_requested,
	noxs_watch_updated
};
typedef enum noxs_watch_state noxs_watch_state_t;


struct noxs_ctrl_hdr {
	int devid;
	int be_state;
	int fe_state;

	noxs_watch_state_t fe_watch_state;
	noxs_watch_state_t be_watch_state;
};
typedef struct noxs_ctrl_hdr noxs_ctrl_hdr_t;

#endif /* XEN_PUBLIC_IO_NOXS_H_ */
