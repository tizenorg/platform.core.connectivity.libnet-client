/*
 * Network Client Library
 *
 * Copyright 2012 Samsung Electronics Co., Ltd
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.tizenopensource.org/license
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __NETWORK_INTERNAL_H__
#define __NETWORK_INTERNAL_H__

#include <dlog.h>
#include <glib.h>
#include <stdlib.h>
#include <gio/gio.h>
#include <glib-object.h>

#include "network-cm-intf.h"
#include "network-wifi-intf.h"

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 * 	Macros and Typedefs
 *****************************************************************************/

/** Maximum Profile Count */
#define NET_PROFILE_LIST_MAX 512

#define NET_TECH_LENGTH_MAX 64

#define CONNMAN_MAX_BUFLEN 512

#define CONNMAN_STATE_STRLEN 16

#define	NET_MEMFREE(x)	{if(x != NULL) free(x); x = NULL;}

#define CONNMAN_SERVICE                 "net.connman"
#define CONNMAN_MANAGER_INTERFACE		CONNMAN_SERVICE ".Manager"
#define CONNMAN_TECHNOLOGY_INTERFACE	CONNMAN_SERVICE ".Technology"
#define CONNMAN_SERVICE_INTERFACE		CONNMAN_SERVICE ".Service"
#define CONNMAN_PROFILE_INTERFACE		CONNMAN_SERVICE ".Profile"
#define CONNMAN_COUNTER_INTERFACE		CONNMAN_SERVICE ".Counter"
#define CONNMAN_ERROR_INTERFACE			CONNMAN_SERVICE ".Error"
#define CONNMAN_AGENT_INTERFACE			CONNMAN_SERVICE ".Agent"

#define CONNMAN_MANAGER_PATH			"/"
#define CONNMAN_PATH					"/net/connman"
#define CONNMAN_TECHNOLOGY_PATH			"/net/connman/technology"

#define NETCONFIG_SERVICE				"net.netconfig"
#define NETCONFIG_NETWORK_INTERFACE		NETCONFIG_SERVICE ".network"
#define NETCONFIG_WIFI_INTERFACE		NETCONFIG_SERVICE ".wifi"
#define NETCONFIG_STATISTICS_INTERFACE	NETCONFIG_SERVICE ".network_statistics"

#define NETCONFIG_NETWORK_PATH			"/net/netconfig/network"
#define NETCONFIG_WIFI_PATH				"/net/netconfig/wifi"
#define NETCONFIG_STATISTICS_PATH		"/net/netconfig/network_statistics"

#if defined TIZEN_TV
#define NETCONFIG_TV_PROFILE_INTERFACE	NETCONFIG_SERVICE ".tv_profile"
#endif

#define TELEPHONY_SERVICE				"com.tcore.ps"
#define TELEPHONY_MASTER_INTERFACE		TELEPHONY_SERVICE ".master"
#define TELEPHONY_MODEM_INTERFACE		TELEPHONY_SERVICE ".modem"
#define TELEPHONY_NETWORK_INTERFACE		TELEPHONY_SERVICE ".network"
#define TELEPHONY_PROFILE_INTERFACE		TELEPHONY_SERVICE ".context"

#define TELEPHONY_MASTER_PATH			"/"
#define TELEPHONY_MODEM_PATH			"/qmimodem0"

#define SUPPLICANT_SERVICE				"fi.w1.wpa_supplicant1"
#define SUPPLICANT_INTERFACE			"fi.w1.wpa_supplicant1"
#define SUPPLICANT_IFACE_INTERFACE		SUPPLICANT_INTERFACE ".Interface"
#define SUPPLICANT_IFACE_BSS			SUPPLICANT_INTERFACE ".BSS"
#define SUPPLICANT_PATH					"/fi/w1/wpa_supplicant1"

#define DBUS_PROPERTIES_INTERFACE		"org.freedesktop.DBus.Properties"

#define CONNMAN_MANAGER_SIGNAL_FILTER \
						"type='signal',interface='net.connman.Manager'"
#define CONNMAN_SERVICE_SIGNAL_FILTER \
						"type='signal',interface='net.connman.Service'"
#define NETCONFIG_WIFI_FILTER \
						"type='signal',interface='net.netconfig.wifi'"
#define SUPPLICANT_INTERFACE_SIGNAL_FILTER \
			"type='signal',interface='fi.w1.wpa_supplicant1.Interface'"

#define SIGNAL_PROPERTY_CHANGED		"PropertyChanged"
#define SIGNAL_PROPERTIES_CHANGED	"PropertiesChanged"
#define SIGNAL_TECHNOLOGY_ADDED		"TechnologyAdded"
#define SIGNAL_TECHNOLOGY_REMOVED	"TechnologyRemoved"
#define SIGNAL_SERVICES_CHANGED		"ServicesChanged"
#define SIGNAL_SCAN_DONE			"ScanDone"

#define CONNMAN_CELLULAR_TECHNOLOGY_PREFIX \
									CONNMAN_PATH "/technology/cellular"
#define CONNMAN_WIFI_TECHNOLOGY_PREFIX \
									CONNMAN_PATH "/technology/wifi"
#define CONNMAN_ETHERNET_TECHNOLOGY_PREFIX \
									CONNMAN_PATH "/technology/ethernet"
#define CONNMAN_BLUETOOTH_TECHNOLOGY_PREFIX \
									CONNMAN_PATH "/technology/bluetooth"

#define CONNMAN_CELLULAR_SERVICE_PROFILE_PREFIX \
									CONNMAN_PATH "/service/cellular_"
#define CONNMAN_WIFI_SERVICE_PROFILE_PREFIX \
									CONNMAN_PATH "/service/wifi_"
#define CONNMAN_ETHERNET_SERVICE_PROFILE_PREFIX \
									CONNMAN_PATH "/service/ethernet_"
#define CONNMAN_BLUETOOTH_SERVICE_PROFILE_PREFIX \
									CONNMAN_PATH "/service/bluetooth_"

/** Network related Daemon Signals */
#define NETCONFIG_SIGNAL_POWERON_COMPLETED	"PowerOnCompleted"
#define NETCONFIG_SIGNAL_POWEROFF_COMPLETED	"PowerOffCompleted"
#define NETCONFIG_SIGNAL_SPECIFIC_SCAN_DONE	"SpecificScanCompleted"
#define NETCONFIG_SIGNAL_WPS_SCAN_DONE		"WpsScanCompleted"
#define NETCONFIG_SIGNAL_ETHERNET_CABLE_STATE	"EthernetCableState"

#undef	LOG_TAG
#define	LOG_TAG		"NET_CLIENT"

#define NETWORK_LOW			1
#define NETWORK_HIGH		2
#define NETWORK_ERROR		3

#define NETWORK_LOG(log_level, format, args...) \
	do { \
		switch (log_level) { \
		case NETWORK_ERROR: \
			SLOGE(format, ##args); \
			break; \
		case NETWORK_HIGH: \
			SLOGI(format, ##args); \
			break; \
		default: \
			SLOGD(format, ##args); \
		} \
	} while(0)

#define SECURE_NETWORK_LOG(log_level, format, args...) \
	do { \
		switch (log_level) { \
		case NETWORK_ERROR: \
			SECURE_SLOGE(format, ##args); \
			break; \
		case NETWORK_HIGH: \
			SECURE_SLOGI(format, ##args); \
			break; \
		default: \
			SECURE_SLOGD(format, ##args); \
		} \
	} while(0)

#define __NETWORK_FUNC_ENTER__	/* NETWORK_LOG(NETWORK_LOW, "Entering (%s)", __func__)*/
#define __NETWORK_FUNC_EXIT__	/* NETWORK_LOG(NETWORK_LOW, "Quit (%s)", __func__)*/

/*****************************************************************************
 * 	Global Enums
 *****************************************************************************/

typedef enum
{
	NETWORK_REQUEST_TYPE_SCAN = 0x00,
	NETWORK_REQUEST_TYPE_OPEN_CONNECTION,
	NETWORK_REQUEST_TYPE_CLOSE_CONNECTION,
	NETWORK_REQUEST_TYPE_WIFI_POWER,
	NETWORK_REQUEST_TYPE_ENROLL_WPS,
	NETWORK_REQUEST_TYPE_SPECIFIC_SCAN,
	NETWORK_REQUEST_TYPE_WPS_SCAN,
	NETWORK_REQUEST_TYPE_SET_DEFAULT,
	NETWORK_REQUEST_TYPE_RESET_DEFAULT,
	NETWORK_REQUEST_TYPE_MAX
} network_async_request_type_t;

typedef struct
{
	int flag;
	char ProfileName[NET_PROFILE_NAME_LEN_MAX+1];
} network_request_table_t;

/*****************************************************************************
 * 	Global Structures
 *****************************************************************************/
typedef struct
{
	int num_of_services;
	char* ProfileName[NET_PROFILE_LIST_MAX];
} network_services_list_t;

typedef struct {
	net_wifi_state_t wifi_state;
	net_event_cb_t ClientEventCb;
	void* user_data;
	net_event_cb_t ClientEventCb_conn;
	void* user_data_conn;
	net_event_cb_t ClientEventCb_wifi;
	void* user_data_wifi;
	int ref_count;
	guint handler_id;
} network_info_t;

typedef struct
{
	char technology[NET_TECH_LENGTH_MAX];
	char AvailableTechnology;
	char EnabledTechnology;
	char ConnectedTechnology;
	char DefaultTechnology;
	/* Connman 1.x */
	char Connected;
	char Powered;
} network_tech_state_info_t;

/**
 * This is the profile structure exposed from modman.
 */
typedef struct
{
	/** Profile name(path) */
	char ProfileName[NET_PROFILE_NAME_LEN_MAX+1];
	/** Service type of this profile context */
	net_service_type_t ServiceType;
	/** Network Access Point Name */
	char Apn[NET_PDP_APN_LEN_MAX+1];
	/** Authentication info of the PDP profile */
	net_auth_info_t AuthInfo;
	/**Proxy address */
	char ProxyAddr[NET_PROXY_LEN_MAX+1];
	/** Browser Home URL or MMS server URL */
	char HomeURL[NET_HOME_URL_LEN_MAX+1];
	char Keyword[NET_PDP_APN_LEN_MAX+1];
	char Hidden;
	char Editable;
	char DefaultConn;
} net_telephony_profile_info_t;

/*****************************************************************************
 * 	Global Functions
 *****************************************************************************/
net_device_t _net_get_tech_type_from_path(const char *profile_name);
int _net_get_tech_state(GVariant *iter, network_tech_state_info_t* tech_state);
char* _net_print_error(net_err_t error);
int _net_is_valid_service_type(net_service_type_t service_type);
int _net_open_connection_with_wifi_info(const net_wifi_connection_info_t* wifi_info);
int _net_check_profile_name(const char* ProfileName);
int _net_get_profile_list(net_device_t device_type, net_profile_info_t** profile_info, int* profile_count);
void _net_client_callback(net_event_info_t *event_data);
int _net_get_service_profile(net_service_type_t service_type, net_profile_name_t *profile_name);
int _net_get_default_profile_info(net_profile_info_t *profile_info);
net_wifi_state_t _net_get_wifi_state(net_err_t *net_error);
void _net_clear_request_table(void);

guint _net_client_callback_add(GSourceFunc func, gpointer user_data);
void _net_client_callback_cleanup(void);

gboolean _net_dbus_is_pending_call_used(void);
void _net_dbus_pending_call_ref(void);
void _net_dbus_pending_call_unref(void);
int _net_dbus_create_gdbus_call(void);
int _net_dbus_close_gdbus_call(void);
GDBusConnection *_net_dbus_get_gdbus_conn(void);
GCancellable *_net_dbus_get_gdbus_cancellable(void);

#ifdef __cplusplus
}
#endif

#endif /* __NETWORK_INTERNAL_H__ */
