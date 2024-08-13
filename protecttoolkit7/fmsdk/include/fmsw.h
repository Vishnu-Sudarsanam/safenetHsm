/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 1997-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: fmsw.h
 */
/**
 * @file Functionality Module Switcher. This module handles directing requests
 * received from the HIFACE to the correct dispatch handler function.
 */
#ifndef INC_FMSW_H
#define INC_FMSW_H

#include <stdint.h>
#include <csa8hiface.h>

/**
 * Error codes for FM Switcher module.
 */
typedef enum {
	/** The function completed OK. */
	FMSW_OK = 0,

	/** There is already a function registered for FM */
	FMSW_ALREADY_REGISTERED,

	/** Invalid FM number */
	FMSW_BAD_FM_NUMBER,

	/** Bad pointer value */
	FMSW_BAD_POINTER,

	/** Not enough memory to complete operation */
	FMSW_INSUFFICIENT_RESOURCES,

	/** The function was not registered for FM */
	FMSW_NOT_REGISTERED,

	/** The FM is currently handling a message */
	FMSW_BUSY,

	/** Message dispatching on FM is blocked. */
	FMSW_DISPATCH_BLOCKED
} FMSW_STATUS;

/**
 * Host events that can cause the notify function to be called.
 */
typedef enum {
	/**
	 * An application communicating with the adapter has terminated. This event
	 * may be omitted on some systems.
	 *
	 * When the notify function is called with this event, the PID of the token
	 * recorded in the current thread will contain the PID of the application
	 * being terminated.
	 */
	FMSW_EVENT_APP_CLOSE,

	/**
	 * The last application communicating with the adapter has terminated. This
	 * event is used as a back-up event for the platforms that cannot support
	 * the @c FMSW_EVENT_APP_CLOSE.
	 *
	 * When the notify function is called with this event, The PID of the token
	 * recorded in the current thread will not have any special
	 * interpretation.
	 */
	FMSW_EVENT_ALL_APPS_CLOSED
} FMSW_HostEvent_t;

/**
 * Possible shutdown types.
 */
typedef enum {
	/** Shutdown: wait for outstanding calls to complete. */
	FMSW_SHUTDOWN_NORMAL,

	/** Shutdown: do not wait for outstanding operations to complete */
	FMSW_SHUTDOWN_EMERGENCY
} FMSW_ShutdownType_t;

/**
 * FM number type.
 */
typedef uint16_t FMSW_FmNumber_t;

/**
 * Special value for FM number, indicating "not an FM"
 */
#define FMSW_INVALID_FM ((FMSW_FmNumber_t)0xFFFFu)

/**
 * Dispatch entry point function pointer type.
 *
 * @param token
 *   A token used to allocate reply buffers, and send the reply back to host.
 *
 * @param reqBuffer
 *   Pointer to the request buffer.
 *
 * @param reqLength
 *   Length of the request buffer.
 */
typedef void (*FMSW_DispatchFn_t)(HI_MsgHandle token, void *reqBuffer, uint32_t reqLength);

/**
 * Host notify entry point type.
 *
 * @param event
 *   The event that has occured on the host system.
 */
typedef void (*FMSW_HostNotifyFn_t)(FMSW_HostEvent_t event);

/**
 * Shutdown entry point type. Normally, shutdown will be called when there is no
 * outstanding host messages. However, under emergency conditions, it can be
 * called while the FM is serving a host message.
 */
typedef void (*FMSW_ShutdownFn_t)( void );

/**
 * Unload entry point type.
 */
typedef void (*FMSW_UnloadFn_t)( void );

/**
 * Initialise the Functionality Module Switcher.
 */
void FMSW_Initialize(void);

/**
 * Register dispatch function. The dispatch function handles the host
 * messages sent to the FM.
 *
 * @param fmNumber
 *   FM Number
 *
 * @param dispatch
 *   Dispatch function pointer.
 *
 * @return
 *   @li FMSW_OK: The function was registered successfully.
 *   @li FMSW_BAD_POINTER: The function pointer is invalid
 *   @li FMSW_INSUFFISICENT_RESOURCES: Not enough memory to complete operation
 *   @li FMSW_BAD_FM_NUMBER: The FM number is incorrect.
 *   @li FMSW_ALREADY_REGISTERED: A dispatch function was already registered.
 */
FMSW_STATUS FMSW_RegisterDispatch(FMSW_FmNumber_t fmNumber,
								  FMSW_DispatchFn_t dispatch);

/**
 * Register a host event notification function. This function gets called when
 * certain events occur on the host system. The types of the events are defined
 * in the enumerated type FMSW_HostEvent_t.
 *
 * @param fmNumber
 *   FM Number.
 *
 * @param notify
 *   Notify function pointer.
 *
 * @return
 *   @li FMSW_OK: The function was registered successfully.
 *   @li FMSW_BAD_POINTER: The function pointer is invalid
 *   @li FMSW_INSUFFISICENT_RESOURCES: Not enough memory to complete operation
 *   @li FMSW_BAD_FM_NUMBER: The FM number is incorrect.
 *   @li FMSW_ALREADY_REGISTERED: A notify function was already registered.
 */
FMSW_STATUS FMSW_RegisterHostNotify(FMSW_FmNumber_t fmNumber,
									FMSW_HostNotifyFn_t notify);

/**
 * Register shutdown function. The shutdown function is called before the system
 * is restarted.
 *
 * @note This functionality is not used in the current firmware.
 *
 * @param fmNumber
 *   FM Number.
 *
 * @param shutdown
 *   Shudown function pointer.
 *
 * Return Value:
 *   @li FMSW_OK: The function was registered successfully.
 *   @li FMSW_BAD_POINTER: The function pointer is invalid
 *   @li FMSW_INSUFFISICENT_RESOURCES: Not enough memory to complete operation
 *   @li FMSW_BAD_FM_NUMBER: The FM number is incorrect.
 *   @li FMSW_ALREADY_REGISTERED: A shutdown function was already registered.
 */
FMSW_STATUS FMSW_RegisterShutdown(FMSW_FmNumber_t fmNumber,
								  FMSW_ShutdownFn_t shutdown);

/**
 * Register an unload function. The unload function will be called
 * when the FM is about to be unloaded.
 *
 * @note This functionality is not used in the current firmware.
 *
 * @param fmNumber
 *   FM Number.
 *
 * @param unload
 *   Unload function pointer.
 *
 * @return
 *   @li FMSW_OK: The function was registered successfully.
 *   @li FMSW_BAD_POINTER: The function pointer is invalid
 *   @li FMSW_INSUFFISICENT_RESOURCES: Not enough memory to complete operation
 *   @li FMSW_BAD_FM_NUMBER: The FM number is incorrect.
 *   @li FMSW_ALREADY_REGISTERED: An unload function was already registered.
 */
FMSW_STATUS FMSW_RegisterUnload(FMSW_FmNumber_t fmNumber,
								FMSW_UnloadFn_t unload);

/**
 * Register callaout table. The callout table is used by other FMs to
 * call functions of the FM.
 *
 * @note This functionality is not used in the current firmware.
 *
 * @param fmNumber
 *   FM Number
 *
 * @param table
 *   Address of the callout table.
 *
 * @return
 *   @li FMSW_OK: The function was registered successfully.
 *   @li FMSW_BAD_POINTER: The function pointer is invalid
 *   @li FMSW_INSUFFISICENT_RESOURCES: Not enough memory to complete operation
 *   @li FMSW_BAD_FM_NUMBER: The FM number is incorrect.
 *   @li FMSW_ALREADY_REGISTERED: A callout table was already registered.
 */
FMSW_STATUS FMSW_RegisterFnTable(FMSW_FmNumber_t fmNumber,
								 const void *table);

/**
 * Deregister a dispatch function. The function will not be called again after
 * this function returns.
 *
 * @param fmNumber
 *   FM Number.
 *
 * @param dispatch
 *   Address of the function to be de-registered. It must match the current
 *   function address.
 *
 * @return
 *   @li FMSW_OK: The function was deregistered OK.
 *   @li FMSW_BAD_FM_NUMBER: The FM number is incorrect.
 *   @li FMSW_NOT_REGISTERED: The function was not registered for fmNumber.
 */
FMSW_STATUS FMSW_DeregisterDispatch(FMSW_FmNumber_t fmNumber,
									FMSW_DispatchFn_t dispatch);

/**
 * Deregister a notify function.
 *
 * @param fmNumber
 *   FM Number.
 *
 * @param notify
 *   Address of the notify function. It must match the currently registered
 *   notify function address.
 *
 * @return
 *   @li FMSW_OK: The function was deregistered OK.
 *   @li FMSW_BAD_FM_NUMBER: The FM number is incorrect.
 *   @li FMSW_NOT_REGISTERED: The function was not registered for fmNumber.
 */
FMSW_STATUS FMSW_DeregisterHostNotify(FMSW_FmNumber_t fmNumber,
									  FMSW_HostNotifyFn_t notify);

/**
 * Deregister a shutdown function.
 *
 * @param fmNumber
 *   FM Number.
 *
 * @param shotdown
 *   Address of the shutdown function to be de-registered. It must match the
 *   currently registered function address.
 *
 * @return
 *   @li FMSW_OK: The function was deregistered OK.
 *   @li FMSW_BAD_FM_NUMBER: The FM number is incorrect.
 *   @li FMSW_NOT_REGISTERED: The function was not registered for fmNumber.
 */
FMSW_STATUS FMSW_DeregisterShutdown(FMSW_FmNumber_t fmNumber,
									FMSW_ShutdownFn_t shutdown);

/**
 * Deregister an unload function.
 *
 * @param fmNumber
 *   FM Number.
 *
 * @param unload
 *   Address of the function to be de-registered. It must match the currently
 *   registered function address.
 *
 * @return
 *   @li FMSW_OK: The function was deregistered OK.
 *   @li FMSW_BAD_FM_NUMBER: The FM number is incorrect.
 *   @li FMSW_NOT_REGISTERED: The function was not registered for fmNumber.
 */
FMSW_STATUS FMSW_DeregisterUnload(FMSW_FmNumber_t fmNumber,
								  FMSW_UnloadFn_t unload);

/**
 * Dispatch a command to a functionality module.
 *
 * @param fmNumber
 *   FM Number.
 *
 * @param token
 *   A token used to allocate reply buffers, and send the reply back to the host.
 *
 * @param reqBuffer
 *   Start address of the request buffer.
 *
 * @param reqLength
 *   Length, in number of bytes, of the request buffer.
 *
 * @return
 *   @li FMSW_OK: The function processed the command OK.
 *   @li FMSW_BAD_FM_NUMBER: The FM number is incorrect.
 *   @li FMSW_NOT_REGISTERED: The functionality module specified has not
 *       registered a dispatch function.
 *   @li FMSW_DISPATCH_BLOCKED: Message dispatching on FM is blocked.
 */
FMSW_STATUS FMSW_CallDispatch(FMSW_FmNumber_t fmNumber,
							  HI_MsgHandle token,
							  void *reqBuffer,
							  uint32_t reqLength);

/**
 * Notify the FM about a host event.
 *
 * @param fmNumber
 *   FM Number.
 *
 * @param event
 *   The event that has occured.
 *
 * @return
 *   @li FMSW_OK: The function processed the command OK.
 *   @li FMSW_BAD_FM_NUMBER: The FM number is incorrect.
 *   @li FMSW_NOT_REGISTERED: The functionality module specified has not
 *                       registered a notify function.
 */
FMSW_STATUS FMSW_CallHostNotify(FMSW_FmNumber_t fmNumber,
								FMSW_HostEvent_t event);

/**
 * Request that a Functionality Module shutdown.
 *
 * @param fmNumber
 *   FM Number.
 *
 * @param sdType
 *   The type of shutdown.
 *
 * @return
 *   @li FMSW_OK: The FM has shutdown OK.
 *   @li FMSW_BAD_FM_NUMBER: The FM number is incorrect.
 *   @li FMSW_NOT_REGISTERED: A shutdown function was not registered for fmNumber.
 */
FMSW_STATUS FMSW_CallShutdown(FMSW_FmNumber_t fmNumber,
							  FMSW_ShutdownType_t sdType);

/**
 * Request a FM to get ready for unload.
 *
 * @param fmNumber
 *   FM Number.
 *
 * @return
 *   @li FMSW_OK: unload function called successfully.
 *   @li FMSW_BAD_FM_NUMBER: The FM number is incorrect.
 *   @li FMSW_NOT_REGISTERED: An unload function was not registered for fmNumber.
 */
FMSW_STATUS FMSW_CallUnload(FMSW_FmNumber_t fmNumber);

/**
 * This function is used to obtain the callout table registered with
 * the specified functionality module.
 *
 * @param fmNumber
 *   FM Number.
 *
 * @param table
 *   Address of the variable that will receive the address of the callout table.
 *
 * @return
 *   @li FMSW_OK: unload function called successfully.
 *   @li BAD_POINTER: the table parameter is not a valid pointer.
 *   @li FMSW_BAD_FM_NUMBER: The FM number is incorrect.
 *   @li FMSW_NOT_REGISTERED: A callout table was not registered for fmNumber.
 */
FMSW_STATUS FMSW_GetFnTable(FMSW_FmNumber_t fmNumber, void **table);

/**
 * Determine if a Functionality Module is currently handling a message dispatch.
 *
 * @param fmNumber
 *    FM Number.
 *
 * Return Value:
 *   @li FMSW_OK: The FM is not busy.
 *   @li FMSW_BAD_FM_NUMBER: The FM number is incorrect.
 *   @li FMSW_NOT_REGISTERED: The FM has not registered a dispatch function.
 *   @li FMSW_BUSY: The FM is processing requests at the moment.
 */
FMSW_STATUS FMSW_IsBusy(FMSW_FmNumber_t fmNumber);

/**
 * Block all calls to a Functionality Module.
 *
 * @param fmNumber
 *    FM Number.
 *
 * @return
 *   @li FMSW_OK: All calls to the FM are now being blocked.
 *   @li FMSW_BAD_FM_NUMBER: The FM number is incorrect.
 *   @li FMSW_NOT_REGISTERED: The functionality module specified has not
 *   registered a dispatch entry point with the switcher.
 */
FMSW_STATUS FMSW_BlockDispatch(FMSW_FmNumber_t fmNumber);

/**
 * Unblock message dispatching on fmNumber.
 *
 * @param fmNumber
 *   FM Number.
 *
 * @return
 *   @li FMSW_OK: Dispatches are allowed to the
 *   @li FMSW_BAD_FM_NUMBER: The FM number is incorrect.
 *   @li FMSW_NOT_REGISTERED: The functionality module specified has not
 *   registered a dispatch entry point with the switcher.
 */
FMSW_STATUS FMSW_UnBlockDispatch(FMSW_FmNumber_t fmNumber);

/**
 * This function is used to enumerate all FMs which registered at least one
 * function. The first FM number is obtained by passing FMSW_INVALID_FM in
 * current. For all subsequent FMs, the FM number obtained should be passed to
 * the function in the 'current' parameter.
 *
 * @param current
 *   The FM number to start the search on. The special value @c FMSW_INVALID_FM
 *   is used to start the search.
 *
 * @return
 *   @li The FM number following 'current'. When 'current is FMSW_INVALID_FM,
 *       the first FM number is returned.
 *   @li If there are no more registered FMs, or the 'current' parameter is
 *       invalid, FMSW_INVALID_FM is returned.
 */
FMSW_FmNumber_t FMSW_GetNextFm(FMSW_FmNumber_t current);

#endif /* INC_FMSW_H */
