/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of the License "Eclipse Public License v1.0"
* which accompanies this distribution, and is available
* at the URL "http://www.eclipse.org/legal/epl-v10.html".
*
* Initial Contributors:
* Nokia Corporation - initial contribution.
*
* Contributors:
*
* Description:  EAP and WLAN authentication protocols.
*
*/

/*
* %version: 22 %
*/


#ifndef EAPSESSION_H_
#define EAPSESSION_H_

#include <e32base.h>
#include <e32std.h>
#include <ecom.h>
#include "EapServerClientDef.h"
#include "EapServer.h"
#include "EapScheduler.h"
#include "eap_am_tools.h"
#include "eap_am_types.h"
#include "SendPacketHandler.h"
#include "EapMessageQueue.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_REAPSESSION_H)
	#define EAP_CLASS_VISIBILITY_REAPSESSION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_REAPSESSION_H 
	#define EAP_C_FUNC_VISIBILITY_REAPSESSION_H 
	#define EAP_FUNC_EXPORT_REAPSESSION_H 
	#define EAP_C_FUNC_EXPORT_REAPSESSION_H 
#elif defined(EAP_EXPORT_REAPSESSION_H)
	#define EAP_CLASS_VISIBILITY_REAPSESSION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_REAPSESSION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_REAPSESSION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_REAPSESSION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_REAPSESSION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_REAPSESSION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_REAPSESSION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_REAPSESSION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_REAPSESSION_H 
	#define EAP_C_FUNC_EXPORT_REAPSESSION_H 
#endif
// End: added by script change_export_macros.sh.


//----------------------------------------------------------------

class MEapolPacketHandler
    {
public:
    virtual void EapolHandleL(const TDesC8& aData) = 0;
    };

//----------------------------------------------------------------

class CSendHandler;
class CEapCoreInterfaceImplementation;
class CEapClientProcessHandler;

//----------------------------------------------------------------

class CEapolPacketHandler : public CBase, public MEapolPacketHandler
    {
    void EapolHandleL(const TDesC8& aData);
private:
    CEapCoreInterfaceImplementation* iClient;
    };

//----------------------------------------------------------------

class EAP_CLASS_VISIBILITY_REAPSESSION_H REapSession :  public RSessionBase
    {
public:

    // construct
    inline REapSession()
		: iSendHandler(0)
		, iProcessHandler(0)
		, iStatus(KErrNone)
		, iTools(0)
		, iClient(0)
		, iEapMessageQueue(0)
	{
	};

	EAP_FUNC_VISIBILITY_REAPSESSION_H virtual ~REapSession();


	EAP_FUNC_VISIBILITY_REAPSESSION_H void ConnectL(
		abs_eap_am_tools_c * const tools,
		MSendPacketHandler * Client,
		const TBuf<KMaxServerExe> ServerName,
		const TBuf<KMaxServerExe> ServerExe,
		const void * const aConfigurationData,
		const TInt aConfigurationDataLength,
		const TEapRequests aIfRequest);

    EAP_FUNC_VISIBILITY_REAPSESSION_H void Close();

    EAP_FUNC_VISIBILITY_REAPSESSION_H bool get_is_valid();
 
    /// Function receives the data message from lower layer.
    /// Data is formatted to Attribute-Value Pairs.
    /// Look at eap_tlv_header_c and eap_tlv_message_data_c.
    EAP_FUNC_VISIBILITY_REAPSESSION_H eap_status_e process_data(const TEapRequests aMessageType, const void * const data, const u32_t length);

	const EapMessageBuffer * GetFirstMessage();

	TInt DeleteFirstMessage();

	void Process(const EapMessageBuffer * const buffer, TRequestStatus &aStatus) const;

private:
    /**
    * Version information.
    * @return Version information.
    */
    TVersion Version() const;

    friend class CSendHandler;

    void Receive(TDes8& aBuffer, TRequestStatus& aStatus);

    void CancelReceive();

    CSendHandler* iSendHandler;

	CEapClientProcessHandler* iProcessHandler;

    TRequestStatus iStatus;

    abs_eap_am_tools_c * iTools;

    MSendPacketHandler* iClient;

    RProcess iServer;

	EapMessageQueue* iEapMessageQueue;
    };

//----------------------------------------------------------------

class CSendHandler : public CActive
    {

public:
    // construct/destruct
    CSendHandler(
		abs_eap_am_tools_c * const tools,
		REapSession& aSession); //MEapolPacketHandler& aHandler, 

    virtual ~CSendHandler();

    // operation
    void Receive();

private:
    // from CActive
    void RunL();
    void DoCancel();
	TInt RunError(TInt aError);


private:

    abs_eap_am_tools_c * iTools;

    REapSession& iSession;

    TBuf8<KMaxEapData> iBuffer;
   
    };

//----------------------------------------------------------------

class CEapClientProcessHandler
: public CActive
    {

public:

    CEapClientProcessHandler(
		abs_eap_am_tools_c * const tools,
		REapSession& aSession);

    virtual ~CEapClientProcessHandler();

	void Activate();

private:

    // from CActive
    void RunL();
    void DoCancel();
	TInt RunError(TInt aError);


private:

    abs_eap_am_tools_c * iTools;

    REapSession& iSession;

	bool iProcessPending;
    };

//----------------------------------------------------------------

#endif /* EAPSESSION_H_ */
