/*
 * Network Client Library
 *
 * Copyright 2011-2013 Samsung Electronics Co., Ltd
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://floralicense.org/license/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __NETWORK_CM_ERROR_H__
#define __NETWORK_CM_ERROR_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup NETLIB Network Client Library
 \{
 <h1 class="pg">Introduction</h1>
 Network Client Library provides specific APIs for interacting with the Network F/W.\n
 Network F/W is based on ConnMan(Connection Manager), which provides cellular and Wi-Fi based network connection.
 <h1 class="pg">Notice</h2>
 Network Client Library doesn't provide certain thread-safety guarantees.\n
 Application should use this library on a single thread only.
 \}
*/

/**
 * @defgroup NETLIB
 \{
 * 	\defgroup common_basic  Basic APIs(connection, registration, etc...)
 * 	\defgroup common_info  APIs for get network information
 * 	\defgroup common_extended  Extended APIs
 * 	\defgroup profile_managing  profile managing APIs
 * 	\defgroup wifi_specific  Wi-Fi specific APIs
 * 	\defgroup pdp_specific  PDP specific APIs
 \}
*/

/**
 * @file network-cm-error.h
 * @brief This file defines the common error code.
*/

/**
 * \addtogroup  common_basic
 * \{
*/

/*
==================================================================================================
                                           CONSTANTS
==================================================================================================
*/
/*
==================================================================================================
                                            MACROS
==================================================================================================
*/

/*
==================================================================================================
                                            Enum
==================================================================================================
*/

/**
 * @enum net_err_t
 * Error Definition
 */

typedef enum {
	/** No error */
	NET_ERR_NONE = 0x00,

	/* Common Error value */

	/** Error unknown */
	NET_ERR_UNKNOWN = -999,

	/* Client Register related Errors used in API return */

	/** Application is already registered */
	NET_ERR_APP_ALREADY_REGISTERED = -990,
	/** Application is not registered */
	NET_ERR_APP_NOT_REGISTERED = -989,

	/* Connection Related Error */

	/** No active connection exists for the given profile name */
	NET_ERR_NO_ACTIVE_CONNECTIONS = -899,
	/** Active connection already exists for the given profile name  */
	NET_ERR_ACTIVE_CONNECTION_EXISTS = -898,

	/** Connection failure : out of range */
	NET_ERR_CONNECTION_OUT_OF_RANGE = -897,
	/** Connection failure : pin missing */
	NET_ERR_CONNECTION_PIN_MISSING = -896,
	/** Connection failure : dhcp failed */
	NET_ERR_CONNECTION_DHCP_FAILED = -895,
	/** Connection failure */
	NET_ERR_CONNECTION_CONNECT_FAILED = -894,
	/** Connection failure : login failed */
	NET_ERR_CONNECTION_LOGIN_FAILED = -893,
	/** Connection failure : authentication failed */
	NET_ERR_CONNECTION_AUTH_FAILED = -892,
	/** Connection failure : invalid key */
	NET_ERR_CONNECTION_INVALID_KEY = -891,

	/* Other Error */

	/** Access(permission) denied */
	NET_ERR_ACCESS_DENIED = -799,
	/** Operation is in progress */
	NET_ERR_IN_PROGRESS = -798,
	/** Operation was aborted by client or network*/
	NET_ERR_OPERATION_ABORTED = -797,
	/** Invalid value of API parameter */
	NET_ERR_INVALID_PARAM = -796,
	/** Invalid operation depending on current state */
	NET_ERR_INVALID_OPERATION = -795,

	/** Feature not supported */
	NET_ERR_NOT_SUPPORTED = -794,
	/** TimeOut Error */
	NET_ERR_TIME_OUT = -793,
	/** Network service is not available */
	NET_ERR_NO_SERVICE = -792,
	/** DBus can't find appropriate method */
	NET_ERR_UNKNOWN_METHOD = -791,
	/** Operation is restricted */
	NET_ERR_SECURITY_RESTRICTED = -790,
	/** Already exists */
	NET_ERR_ALREADY_EXISTS = -789,

	/** WiFi driver on/off failed */
	NET_ERR_WIFI_DRIVER_FAILURE = -699,
	NET_ERR_WIFI_DRIVER_LOAD_INPROGRESS = -698,
} net_err_t;

/*
==================================================================================================
                                 STRUCTURES AND OTHER TYPEDEFS
==================================================================================================
*/

/*
==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================
*/

/**
 * \}
 */

#ifdef __cplusplus
}
#endif
 
#endif
