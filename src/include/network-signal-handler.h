/*
 *
 * Network Client Library
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd All Rights Reserved.
 *
 * PROPRIETARY/CONFIDENTIAL
 * This software is the confidential and proprietary information of
 * SAMSUNG ELECTRONICS ("Confidential Information").
 * You shall not disclose such Confidential Information and shall
 * use it only in accordance with the terms of the license agreement
 * you entered into with SAMSUNG ELECTRONICS.
 * SAMSUNG make no representations or warranties about the suitability
 * of the software, either express or implied, including but not limited
 * to the implied warranties of merchantability, fitness for a particular
 * purpose, or non-infringement. SAMSUNG shall not be liable for
 * any damages suffered by licensee as a result of using, modifying or
 * distributing this software or its derivatives.
 *
 */


#ifndef __NETWORK_SIGNAL_HANDLER_H_
#define __NETWORK_SIGNAL_HANDLER_H_

/*****************************************************************************
 * 	Standard headers
 *****************************************************************************/
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include <dbus/dbus.h> 


/*****************************************************************************
 * 	Platform headers
 *****************************************************************************/

/*****************************************************************************
 * 	Macros and Typedefs
 *****************************************************************************/

/*****************************************************************************
 * 	Global Structures
 *****************************************************************************/

/*****************************************************************************
 * 	Global Functions 
 *****************************************************************************/
int _net_deregister_signal(void);
int network_register_and_recieve_signal(void);
int _net_register_signal(void);
int _net_init_service_state_table(void);


#endif /** __NETWORK_SIGNAL_HANDLER_H_ */

