/*
 *  Network Client Library
 *
* Copyright 2012  Samsung Electronics Co., Ltd

* Licensed under the Flora License, Version 1.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at

* http://www.tizenopensource.org/license

* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
 *
 */


#ifndef __NETWORK_PM_CONFIG_H__
#define __NETWORK_PM_CONFIG_H__


#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/**
 * @file network-pm-config.h
 * @brief This file defines the constants and enumerations used by Profile Manager with the application/Connection Manager.
*/

/**
 * \addtogroup  profile_managing
 * \{
*/

/*==================================================================================================
                                         INCLUDE FILES
==================================================================================================*/

#include <netinet/in.h>

#include "network-cm-error.h"

/*==================================================================================================
                                           CONSTANTS
==================================================================================================*/

/** Profile name max length */
#define NET_PROFILE_NAME_LEN_MAX 512

/** Home URL max length in profile account */
#define NET_HOME_URL_LEN_MAX 512

/** Maximum length of IPv4 string type e.g., "165.213.173.105". This length does not include NULL in the last byte. */
#define NETPM_IPV4_STR_LEN_MAX 15

/** Minimum length of IPv4 string type e.g., "0.0.0.0". This length does not include NULL in the last byte. */
#define NETPM_IPV4_STR_LEN_MIN 7

/** This is for MCC + MNC string */
#define NET_SIM_INFO_LEN 10

/** Maximum length of username in PDP profile. (used in authentication parameters) [3GPP Defined variable] */
#define NET_PDP_AUTH_USERNAME_LEN_MAX 32 

/** Maximum length of password in PDP profile (used in authentication parameters) [3GPP Defined variable] */
#define NET_PDP_AUTH_PASSWORD_LEN_MAX 32

/** Maximum length of APN in PDP profile [3GPP Defined variable] */
#define NET_PDP_APN_LEN_MAX 100

/** Maximum length of proxy string */
#define NET_PROXY_LEN_MAX 64

/** MAX number of DNS Address */
#define	NET_DNS_ADDR_MAX 2

/** Maximum length of device name  */
#define	NET_MAX_DEVICE_NAME_LEN 32

/** Maximum length of MAC address  */
#define	NET_MAX_MAC_ADDR_LEN 32

/*==================================================================================================
                                             ENUMS
==================================================================================================*/

/**
 * @enum net_device_t
 * Profile Type
 */
typedef enum
{
	/** Unknown device */
	NET_DEVICE_UNKNOWN = 0x0,

	/** Default device */
	NET_DEVICE_DEFAULT = 0x1,

	/** GPRS & WCDMA device */
	NET_DEVICE_CELLULAR = 0x2,

	/** WLAN device */
	NET_DEVICE_WIFI = 0x3,

	/** Serial USB device */
	NET_DEVICE_USB = 0x4,

	/** Ethernet device */
	NET_DEVICE_ETHERNET = 0x5,

	/** Count of device type */
	NET_DEVICE_MAX = 0x6,
} net_device_t;

/**
 * @enum net_addr_type_t
 * Address Type
 */
typedef enum
{

	/** IPV4 Address type */
	NET_ADDR_IPV4 = 0x0,

	/** IPV6 Address type */
	NET_ADDR_IPV6 = 0x1,
} net_addr_type_t;

/**
 * @enum net_auth_type_t
 * PDP Authentication Type
 */
typedef enum
{

	/** No authentication */
	NET_PDP_AUTH_NONE 	= 0x0,

	/** PAP authentication */
	NET_PDP_AUTH_PAP 	= 0x1,

	/** CHAP authentication */
	NET_PDP_AUTH_CHAP 	= 0x2,
} net_auth_type_t;

/**
 * @enum net_proxy_type_t
 * This enumeration defines the proxy method type.
 */
typedef enum
{
	/** Not defined */
	NET_PROXY_TYPE_UNKNOWN	= 0x00, 
	/** Direct connection */
	NET_PROXY_TYPE_DIRECT = 0x01,
	/** Auto configuration(Use PAC file)
	 *  If URL property is not set, DHCP/WPAD auto-discover will be tried */
	NET_PROXY_TYPE_AUTO = 0x02,
	/** Manual configuration */
	NET_PROXY_TYPE_MANUAL= 0x03,
} net_proxy_type_t;

/**
* @enum net_service_type_t
* This enum indicates network connection type
*/
typedef enum
{
	/** Unknown type \n
	*/
	NET_SERVICE_UNKNOWN = 0x00,

	/** Mobile Internet Type \n
		Network connection is established in Cellular network for Internet \n
	*/
	NET_SERVICE_INTERNET = 0x01,

	/** Mobile MMS Type \n
		Network connection is established in Cellular network for MMS \n
	*/
	NET_SERVICE_MMS = 0x02,

	/** Mobile WAP Type \n
		Network connection is established in Cellular network for WAP \n
	*/
	NET_SERVICE_WAP = 0x03,

	/** Prepaid Mobile Internet Type \n
		Network connection is established in Cellular network for prepaid internet service.\n
		This service supports to establish network connection in prepaid sim case\n
	*/
	NET_SERVICE_PREPAID_INTERNET = 0x04,

	/** Prepaid Mobile MMS Type \n
		Network Connection is established in Cellular network for prepaid MMS service. \n
		This profile supports to establish network connection in prepaid sim case\n
	*/
	NET_SERVICE_PREPAID_MMS = 0x05,
} net_service_type_t;


/**
 * @enum net_ip_config_type_t
 * Net IP configuration Type
 */
typedef enum
{
	/** Manual IP configuration */
	NET_IP_CONFIG_TYPE_STATIC = 0x01,

	/** Config ip using DHCP client*/
	NET_IP_CONFIG_TYPE_DYNAMIC,

	/** Config IP from Auto IP pool (169.254/16)
	 * Later with DHCP client, if available */
	NET_IP_CONFIG_TYPE_AUTO_IP,

	/** Indicates an IP address that can not be modified */
	NET_IP_CONFIG_TYPE_FIXED,

	/** Don't use any method */
	NET_IP_CONFIG_TYPE_OFF,
} net_ip_config_type_t;

/*==================================================================================================
                                 STRUCTURES AND OTHER TYPEDEFS
==================================================================================================*/

/**
 * IP Address
 */
typedef union
{
	/** IP Version 4 address */
	struct in_addr           Ipv4;

	/** IP Version 6 address */
	struct in6_addr          Ipv6;
} ip_addr_t;

/**
 * Network Address information
 */
typedef struct
{
	/** Address Type: IPv4 or IPv6 */
	net_addr_type_t Type;

	/** IP Address */
	ip_addr_t Data;
} net_addr_t;

/**
 * Below structure is used to export proxy info
 */
typedef struct
{
	/** Proxy info */
	char			proxy_addr[NET_PROXY_LEN_MAX+1];
} net_proxy_t;

/**
 * Below structure is used to export profile name
 */
typedef struct
{
	/** Profile name */
	char			ProfileName[NET_PROFILE_NAME_LEN_MAX+1];
} net_profile_name_t;

/**
 * PDP Authentication Information
 */
typedef struct
{
	/** Authentication type  */
	net_auth_type_t 	AuthType;

	/** UserName to be used during authentication */
	char 			UserName[NET_PDP_AUTH_USERNAME_LEN_MAX+1];

	/** Password to be used during authentication */
	char 			Password[NET_PDP_AUTH_PASSWORD_LEN_MAX+1];
} net_auth_info_t;

/**
 * Device Info in Connect response event
 */
typedef struct
{
	/** Profile Name of the connection link */
	char		ProfileName[NET_PROFILE_NAME_LEN_MAX+1];

	/** Device Name of the connection link */
	char		DevName[NET_MAX_DEVICE_NAME_LEN+1];

	/** Dns Server Address of the connection link */
	net_addr_t	DnsAddr[NET_DNS_ADDR_MAX];
	/** No of DNS Address for the connection link */
	int		DnsCount;

	/** Net IP configuration Type */
	net_ip_config_type_t IpConfigType;

	/** IP Address for the connection link */
	net_addr_t	IpAddr;
	/** Whether subnet mask present or not. */
	char		BNetmask;
	/** Subnet mask */
	net_addr_t	SubnetMask;
	/** Whether gateway address present or not */
	char		BDefGateway;
	/** Gateway address */
	net_addr_t	GatewayAddr;

	/** Proxy Method type */
	net_proxy_type_t	ProxyMethod;
	/** Proxy address */
	char			ProxyAddr[NET_PROXY_LEN_MAX+1];

	/** MAC address */
	char			MacAddr[NET_MAX_MAC_ADDR_LEN+1];
} net_dev_info_t;

/**
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif


